# Kubernetes Deployment

This page captures the recommended native Kubernetes manifests for
running `coauth` as a stateless authorization server in front of a
PostgreSQL StatefulSet, plus a Helm chart skeleton operators can copy
into their own packaging.

`coauth` itself is stateless — the source of truth is the database.
PostgreSQL should be deployed as a StatefulSet (or, in production, an
external managed instance such as RDS / CloudSQL); `coauth` itself runs
as a horizontally-scaled Deployment.

## Health endpoints

`coauth` exposes three health endpoints via the `health` listener
resource (see [Observability](./observability.md)):

- `/healthz` — liveness; confirms the process is responsive and that
  the Postgres pool is reachable.
- `/readyz` — readiness; additionally confirms the public JWKS can be
  materialized from signing keys, so the pod is safe to receive
  traffic.
- `/metrics` — Prometheus exposition (separate listener; do not expose
  publicly).

## Native Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coauth
  namespace: auth
  labels:
    app.kubernetes.io/name: coauth
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
      maxSurge: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: coauth
  template:
    metadata:
      labels:
        app.kubernetes.io/name: coauth
    spec:
      serviceAccountName: coauth
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: coauth
          image: ghcr.io/cokret-dev/coauth:1.0.0
          imagePullPolicy: IfNotPresent
          args: ["server", "--config", "/etc/coauth/config.yaml"]
          ports:
            - name: http
              containerPort: 8080
            - name: metrics
              containerPort: 9091
          env:
            - name: COAUTH_METRICS_BIND
              value: "0.0.0.0:9091"
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: coauth-db
                  key: url
          livenessProbe:
            httpGet:
              path: /healthz
              port: http
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 2
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /readyz
              port: http
            initialDelaySeconds: 3
            periodSeconds: 5
            timeoutSeconds: 2
            failureThreshold: 2
          resources:
            requests:
              cpu: 200m
              memory: 256Mi
            limits:
              cpu: 1000m
              memory: 512Mi
          volumeMounts:
            - name: config
              mountPath: /etc/coauth
              readOnly: true
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
      volumes:
        - name: config
          configMap:
            name: coauth-config
```

## Postgres StatefulSet (development; use managed Postgres in prod)

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: coauth-postgres
  namespace: auth
spec:
  serviceName: coauth-postgres
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: coauth-postgres
  template:
    metadata:
      labels:
        app.kubernetes.io/name: coauth-postgres
    spec:
      containers:
        - name: postgres
          image: postgres:15.3
          ports: [{ containerPort: 5432, name: pg }]
          env:
            - name: POSTGRES_DB
              value: coauth
            - name: POSTGRES_USER
              valueFrom: { secretKeyRef: { name: coauth-db, key: user } }
            - name: POSTGRES_PASSWORD
              valueFrom: { secretKeyRef: { name: coauth-db, key: password } }
          readinessProbe:
            exec: { command: ["pg_isready", "-U", "$(POSTGRES_USER)"] }
            initialDelaySeconds: 5
            periodSeconds: 5
          livenessProbe:
            exec: { command: ["pg_isready", "-U", "$(POSTGRES_USER)"] }
            initialDelaySeconds: 30
            periodSeconds: 15
          volumeMounts:
            - name: data
              mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
    - metadata: { name: data }
      spec:
        accessModes: ["ReadWriteOnce"]
        resources: { requests: { storage: 20Gi } }
```

## Helm chart skeleton

A minimal Helm chart lives under `charts/coauth/`. The shape is:

```text
charts/coauth/
  Chart.yaml
  values.yaml
  templates/
    _helpers.tpl
    deployment.yaml
    service.yaml
    configmap.yaml
    serviceaccount.yaml
    pdb.yaml
    hpa.yaml
    networkpolicy.yaml
```

Install with:

```sh
helm install coauth ./charts/coauth \
  --namespace auth --create-namespace \
  --set image.tag=1.0.0 \
  --set database.urlSecret=coauth-db
```

The chart intentionally does **not** package PostgreSQL; depend on a
managed Postgres or an external chart (e.g. `bitnami/postgresql`) and
inject the connection URL through `database.urlSecret`.

Production operators should review `podDisruptionBudget`, `autoscaling`, and
`networkPolicy` values before rollout. When `networkPolicy.enabled=true`, egress
is limited to DNS plus the relevant Postgres, upstream OIDC, and soland CIDR
blocks listed in values.

## Debugging a distroless container

`coauth` images are distroless and contain no shell, package manager,
or coreutils. Standard `kubectl exec -it … -- sh` will fail. Operators
have three supported patterns:

1. **`kubectl debug` ephemeral container** — attaches a busybox /
   debug-tools container that shares the target pod's process and
   network namespaces. The `coauth` container itself is untouched.

   ```sh
   kubectl debug -n auth pod/coauth-7c89b6f5d9-abcde \
     --image=busybox:1.36 \
     --target=coauth \
     -it
   ```

   From the ephemeral container you can `wget http://localhost:8080/readyz`,
   inspect `/proc/<pid>/`, and read open sockets through `/proc/net/tcp`.

2. **Sidecar tools container** — for persistent debugging (e.g. a
   staging cluster), attach a long-running sidecar with strace / curl
   to the Deployment template. Disable in production via Helm values.

3. **Pull logs and metrics** — most production issues should be
   resolvable from logs (`kubectl logs`), Prometheus (`/metrics`), and
   traces (OTLP exporter). The distroless image is intentional: no
   shell means no attack surface for shell-based exploits.

Do **not** rebuild the production image with `busybox` baked in to
"make debugging easier" — that defeats the security posture.

## Network policy

Restrict the database namespace and only allow `coauth` pods to reach
Postgres on port 5432. Expose `/metrics` only inside the cluster; never
publish port 9091 through an ingress.
