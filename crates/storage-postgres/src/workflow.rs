// Workflow repository -- PostgreSQL implementation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::workflow::{
    NewWorkflowEvent, NewWorkflowInstance, NewWorkflowStep, WorkflowRepository,
};
use coauth_data::{
    Clock, WorkflowEvent, WorkflowEventKind, WorkflowInstance, WorkflowInstanceStatus,
    WorkflowStep, WorkflowStepStatus, new_id,
};
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use rand_core::RngCore;
use serde::de::DeserializeOwned;
use ulid::Ulid;
use uuid::Uuid;

use crate::schema::{workflow_events, workflow_instances, workflow_steps};
use crate::{DatabaseError, DatabaseInconsistencyError};

/// PostgreSQL implementation of [`WorkflowRepository`].
pub struct PgWorkflowRepository<'c> {
    conn: &'c mut diesel_async::AsyncPgConnection,
}

impl<'c> PgWorkflowRepository<'c> {
    /// Create a new [`PgWorkflowRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut diesel_async::AsyncPgConnection) -> Self {
        Self { conn }
    }
}

// ── Row types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = workflow_instances)]
struct WorkflowInstanceRow {
    id: Uuid,
    workflow_key: String,
    subject: serde_json::Value,
    trigger: serde_json::Value,
    status: String,
    current_step_key: Option<String>,
    input: serde_json::Value,
    context: serde_json::Value,
    correlation_key: Option<String>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    failed_at: Option<DateTime<Utc>>,
    cancelled_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<WorkflowInstanceRow> for WorkflowInstance {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: WorkflowInstanceRow) -> Result<Self, Self::Error> {
        let id = value.id.into();

        Ok(WorkflowInstance {
            id,
            workflow_key: value.workflow_key,
            subject: deserialize_json("workflow_instances", "subject", id, value.subject)?,
            trigger: deserialize_json("workflow_instances", "trigger", id, value.trigger)?,
            status: parse_instance_status(&value.status, id)?,
            current_step_key: value.current_step_key,
            input: value.input,
            context: value.context,
            correlation_key: value.correlation_key,
            started_at: value.started_at,
            completed_at: value.completed_at,
            failed_at: value.failed_at,
            cancelled_at: value.cancelled_at,
            expires_at: value.expires_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = workflow_steps)]
struct WorkflowStepRow {
    id: Uuid,
    workflow_instance_id: Uuid,
    step_key: String,
    sequence: i32,
    status: String,
    assignee: Option<serde_json::Value>,
    input: serde_json::Value,
    output: Option<serde_json::Value>,
    attempt_count: i32,
    last_error_code: Option<String>,
    last_error_message: Option<String>,
    scheduled_at: Option<DateTime<Utc>>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    failed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<WorkflowStepRow> for WorkflowStep {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: WorkflowStepRow) -> Result<Self, Self::Error> {
        let id = value.id.into();

        Ok(WorkflowStep {
            id,
            workflow_instance_id: value.workflow_instance_id.into(),
            step_key: value.step_key,
            sequence: value.sequence.try_into().map_err(|e| {
                DatabaseInconsistencyError::on("workflow_steps")
                    .column("sequence")
                    .row(id)
                    .source(e)
            })?,
            status: parse_step_status(&value.status, id)?,
            assignee: value
                .assignee
                .map(|a| deserialize_json("workflow_steps", "assignee", id, a))
                .transpose()?,
            input: value.input,
            output: value.output,
            attempt_count: value.attempt_count.try_into().map_err(|e| {
                DatabaseInconsistencyError::on("workflow_steps")
                    .column("attempt_count")
                    .row(id)
                    .source(e)
            })?,
            last_error_code: value.last_error_code,
            last_error_message: value.last_error_message,
            scheduled_at: value.scheduled_at,
            started_at: value.started_at,
            completed_at: value.completed_at,
            failed_at: value.failed_at,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = workflow_events)]
struct WorkflowEventRow {
    id: Uuid,
    workflow_instance_id: Uuid,
    workflow_step_id: Option<Uuid>,
    kind: String,
    actor: serde_json::Value,
    payload: serde_json::Value,
    occurred_at: DateTime<Utc>,
}

impl TryFrom<WorkflowEventRow> for WorkflowEvent {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: WorkflowEventRow) -> Result<Self, Self::Error> {
        let id = value.id.into();

        Ok(WorkflowEvent {
            id,
            workflow_instance_id: value.workflow_instance_id.into(),
            workflow_step_id: value.workflow_step_id.map(Into::into),
            kind: parse_event_kind(&value.kind, id)?,
            actor: deserialize_json("workflow_events", "actor", id, value.actor)?,
            payload: value.payload,
            occurred_at: value.occurred_at,
        })
    }
}

// ── Insertable types ─────────────────────────────────────────────────

#[derive(Insertable)]
#[diesel(table_name = workflow_instances)]
struct InsertableWorkflowInstance {
    id: Uuid,
    workflow_key: String,
    subject: serde_json::Value,
    trigger: serde_json::Value,
    status: String,
    current_step_key: Option<String>,
    input: serde_json::Value,
    context: serde_json::Value,
    correlation_key: Option<String>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    failed_at: Option<DateTime<Utc>>,
    cancelled_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = workflow_steps)]
struct InsertableWorkflowStep {
    id: Uuid,
    workflow_instance_id: Uuid,
    step_key: String,
    sequence: i32,
    status: String,
    assignee: Option<serde_json::Value>,
    input: serde_json::Value,
    output: Option<serde_json::Value>,
    attempt_count: i32,
    last_error_code: Option<String>,
    last_error_message: Option<String>,
    scheduled_at: Option<DateTime<Utc>>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    failed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = workflow_events)]
struct InsertableWorkflowEvent {
    id: Uuid,
    workflow_instance_id: Uuid,
    workflow_step_id: Option<Uuid>,
    kind: String,
    actor: serde_json::Value,
    payload: serde_json::Value,
    occurred_at: DateTime<Utc>,
}

// ── Repository implementation ────────────────────────────────────────

#[async_trait]
impl WorkflowRepository for PgWorkflowRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.workflow.lookup_instance",
        skip_all,
        fields(workflow_instance.id = %id),
        err,
    )]
    async fn lookup_instance(&mut self, id: Ulid) -> Result<Option<WorkflowInstance>, Self::Error> {
        let row = workflow_instances::table
            .find(Uuid::from(id))
            .select(WorkflowInstanceRow::as_select())
            .first::<WorkflowInstanceRow>(self.conn)
            .await
            .optional()?;

        row.map(TryInto::try_into).transpose().map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.workflow.add_instance",
        skip_all,
        fields(
            workflow_instance.id,
            workflow_instance.workflow_key = params.workflow_key(),
        ),
        err,
    )]
    async fn add_instance(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewWorkflowInstance,
    ) -> Result<WorkflowInstance, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("workflow_instance.id", tracing::field::display(id));

        let subject =
            serde_json::to_value(params.subject()).map_err(DatabaseError::to_invalid_operation)?;
        let trigger =
            serde_json::to_value(params.trigger()).map_err(DatabaseError::to_invalid_operation)?;

        let row = InsertableWorkflowInstance {
            id: Uuid::from(id),
            workflow_key: params.workflow_key().to_owned(),
            subject,
            trigger,
            status: instance_status_to_db(WorkflowInstanceStatus::Pending).to_owned(),
            current_step_key: None,
            input: params.input().clone(),
            context: serde_json::Value::Object(serde_json::Map::new()),
            correlation_key: params.correlation_key().map(ToOwned::to_owned),
            started_at: None,
            completed_at: None,
            failed_at: None,
            cancelled_at: None,
            expires_at: params.expiration(),
            created_at,
            updated_at: created_at,
        };

        diesel::insert_into(workflow_instances::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(WorkflowInstance {
            id,
            workflow_key: row.workflow_key,
            subject: params.subject().clone(),
            trigger: params.trigger().clone(),
            status: WorkflowInstanceStatus::Pending,
            current_step_key: None,
            input: row.input,
            context: row.context,
            correlation_key: row.correlation_key,
            started_at: None,
            completed_at: None,
            failed_at: None,
            cancelled_at: None,
            expires_at: row.expires_at,
            created_at,
            updated_at: created_at,
        })
    }

    #[tracing::instrument(
        name = "db.workflow.set_instance_status",
        skip_all,
        fields(
            workflow_instance.id = %workflow_instance.id,
            workflow_instance.status = ?status,
        ),
        err,
    )]
    async fn set_instance_status(
        &mut self,
        clock: &dyn Clock,
        mut workflow_instance: WorkflowInstance,
        status: WorkflowInstanceStatus,
    ) -> Result<WorkflowInstance, Self::Error> {
        let now = clock.now();

        workflow_instance.status = status;
        workflow_instance.updated_at = now;

        match status {
            WorkflowInstanceStatus::Pending => {
                workflow_instance.started_at = None;
                workflow_instance.completed_at = None;
                workflow_instance.failed_at = None;
                workflow_instance.cancelled_at = None;
            }
            WorkflowInstanceStatus::Active => {
                workflow_instance.started_at.get_or_insert(now);
                workflow_instance.completed_at = None;
                workflow_instance.failed_at = None;
                workflow_instance.cancelled_at = None;
            }
            WorkflowInstanceStatus::Waiting => {
                workflow_instance.started_at.get_or_insert(now);
            }
            WorkflowInstanceStatus::Succeeded => {
                workflow_instance.started_at.get_or_insert(now);
                workflow_instance.completed_at = Some(now);
            }
            WorkflowInstanceStatus::Failed => {
                workflow_instance.started_at.get_or_insert(now);
                workflow_instance.failed_at = Some(now);
            }
            WorkflowInstanceStatus::Cancelled => {
                workflow_instance.cancelled_at = Some(now);
            }
            WorkflowInstanceStatus::Expired => {
                workflow_instance.cancelled_at = Some(now);
            }
        }

        let rows_affected = diesel::update(
            workflow_instances::table
                .filter(workflow_instances::id.eq(Uuid::from(workflow_instance.id))),
        )
        .set((
            workflow_instances::status.eq(instance_status_to_db(workflow_instance.status)),
            workflow_instances::started_at.eq(workflow_instance.started_at),
            workflow_instances::completed_at.eq(workflow_instance.completed_at),
            workflow_instances::failed_at.eq(workflow_instance.failed_at),
            workflow_instances::cancelled_at.eq(workflow_instance.cancelled_at),
            workflow_instances::updated_at.eq(workflow_instance.updated_at),
        ))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(workflow_instance)
    }

    #[tracing::instrument(
        name = "db.workflow.lookup_step",
        skip_all,
        fields(workflow_step.id = %id),
        err,
    )]
    async fn lookup_step(&mut self, id: Ulid) -> Result<Option<WorkflowStep>, Self::Error> {
        let row = workflow_steps::table
            .find(Uuid::from(id))
            .select(WorkflowStepRow::as_select())
            .first::<WorkflowStepRow>(self.conn)
            .await
            .optional()?;

        row.map(TryInto::try_into).transpose().map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.workflow.list_steps",
        skip_all,
        fields(workflow_instance.id = %workflow_instance.id),
        err,
    )]
    async fn list_steps(
        &mut self,
        workflow_instance: &WorkflowInstance,
    ) -> Result<Vec<WorkflowStep>, Self::Error> {
        workflow_steps::table
            .filter(workflow_steps::workflow_instance_id.eq(Uuid::from(workflow_instance.id)))
            .order(workflow_steps::sequence.asc())
            .select(WorkflowStepRow::as_select())
            .load::<WorkflowStepRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    #[tracing::instrument(
        name = "db.workflow.add_step",
        skip_all,
        fields(
            workflow_instance.id = %workflow_instance.id,
            workflow_step.id,
            workflow_step.step_key = params.step_key(),
        ),
        err,
    )]
    async fn add_step(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        workflow_instance: &WorkflowInstance,
        params: NewWorkflowStep,
    ) -> Result<WorkflowStep, Self::Error> {
        let created_at = clock.now();
        let id = new_id(created_at, rng);
        tracing::Span::current().record("workflow_step.id", tracing::field::display(id));

        let assignee = params
            .assignee()
            .map(serde_json::to_value)
            .transpose()
            .map_err(DatabaseError::to_invalid_operation)?;

        let sequence: i32 = params
            .sequence()
            .try_into()
            .map_err(|_| DatabaseError::invalid_operation())?;

        let row = InsertableWorkflowStep {
            id: Uuid::from(id),
            workflow_instance_id: Uuid::from(workflow_instance.id),
            step_key: params.step_key().to_owned(),
            sequence,
            status: step_status_to_db(WorkflowStepStatus::Pending).to_owned(),
            assignee,
            input: params.input().clone(),
            output: None,
            attempt_count: 0,
            last_error_code: None,
            last_error_message: None,
            scheduled_at: None,
            started_at: None,
            completed_at: None,
            failed_at: None,
            created_at,
            updated_at: created_at,
        };

        diesel::insert_into(workflow_steps::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(WorkflowStep {
            id,
            workflow_instance_id: workflow_instance.id,
            step_key: row.step_key,
            sequence: params.sequence(),
            status: WorkflowStepStatus::Pending,
            assignee: params.assignee().cloned(),
            input: row.input,
            output: None,
            attempt_count: 0,
            last_error_code: None,
            last_error_message: None,
            scheduled_at: None,
            started_at: None,
            completed_at: None,
            failed_at: None,
            created_at,
            updated_at: created_at,
        })
    }

    #[tracing::instrument(
        name = "db.workflow.set_step_status",
        skip_all,
        fields(
            workflow_step.id = %workflow_step.id,
            workflow_step.status = ?status,
        ),
        err,
    )]
    async fn set_step_status(
        &mut self,
        clock: &dyn Clock,
        mut workflow_step: WorkflowStep,
        status: WorkflowStepStatus,
    ) -> Result<WorkflowStep, Self::Error> {
        let now = clock.now();

        workflow_step.status = status;
        workflow_step.updated_at = now;

        match status {
            WorkflowStepStatus::Pending => {
                workflow_step.scheduled_at = None;
                workflow_step.started_at = None;
                workflow_step.completed_at = None;
                workflow_step.failed_at = None;
            }
            WorkflowStepStatus::Scheduled => {
                workflow_step.scheduled_at.get_or_insert(now);
            }
            WorkflowStepStatus::Running => {
                workflow_step.started_at.get_or_insert(now);
                workflow_step.attempt_count = workflow_step.attempt_count.saturating_add(1);
            }
            WorkflowStepStatus::Waiting => {}
            WorkflowStepStatus::Succeeded => {
                workflow_step.completed_at = Some(now);
            }
            WorkflowStepStatus::Failed => {
                workflow_step.failed_at = Some(now);
            }
            WorkflowStepStatus::Cancelled => {
                workflow_step.failed_at = Some(now);
            }
            WorkflowStepStatus::Skipped => {
                workflow_step.completed_at = Some(now);
            }
        }

        let attempt_count: i32 = workflow_step
            .attempt_count
            .try_into()
            .map_err(|_| DatabaseError::invalid_operation())?;

        let rows_affected = diesel::update(
            workflow_steps::table.filter(workflow_steps::id.eq(Uuid::from(workflow_step.id))),
        )
        .set((
            workflow_steps::status.eq(step_status_to_db(workflow_step.status)),
            workflow_steps::attempt_count.eq(attempt_count),
            workflow_steps::scheduled_at.eq(workflow_step.scheduled_at),
            workflow_steps::started_at.eq(workflow_step.started_at),
            workflow_steps::completed_at.eq(workflow_step.completed_at),
            workflow_steps::failed_at.eq(workflow_step.failed_at),
            workflow_steps::updated_at.eq(workflow_step.updated_at),
        ))
        .execute(self.conn)
        .await?;

        DatabaseError::ensure_affected_rows_usize(rows_affected, 1)?;

        Ok(workflow_step)
    }

    #[tracing::instrument(
        name = "db.workflow.append_event",
        skip_all,
        fields(
            workflow_instance.id = %workflow_instance.id,
            workflow_event.kind = ?params.kind(),
        ),
        err,
    )]
    async fn append_event(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        workflow_instance: &WorkflowInstance,
        workflow_step: Option<&WorkflowStep>,
        params: NewWorkflowEvent,
    ) -> Result<WorkflowEvent, Self::Error> {
        let occurred_at = clock.now();
        let id = new_id(occurred_at, rng);

        let row = InsertableWorkflowEvent {
            id: Uuid::from(id),
            workflow_instance_id: Uuid::from(workflow_instance.id),
            workflow_step_id: workflow_step.map(|s| Uuid::from(s.id)),
            kind: event_kind_to_db(params.kind()).to_owned(),
            actor: serde_json::to_value(params.actor())
                .map_err(DatabaseError::to_invalid_operation)?,
            payload: params.payload().clone(),
            occurred_at,
        };

        diesel::insert_into(workflow_events::table)
            .values(&row)
            .execute(self.conn)
            .await?;

        Ok(WorkflowEvent {
            id,
            workflow_instance_id: workflow_instance.id,
            workflow_step_id: workflow_step.map(|s| s.id),
            kind: params.kind(),
            actor: params.actor().clone(),
            payload: row.payload,
            occurred_at,
        })
    }

    #[tracing::instrument(
        name = "db.workflow.list_events",
        skip_all,
        fields(workflow_instance.id = %workflow_instance.id),
        err,
    )]
    async fn list_events(
        &mut self,
        workflow_instance: &WorkflowInstance,
    ) -> Result<Vec<WorkflowEvent>, Self::Error> {
        workflow_events::table
            .filter(workflow_events::workflow_instance_id.eq(Uuid::from(workflow_instance.id)))
            .order((
                workflow_events::occurred_at.asc(),
                workflow_events::id.asc(),
            ))
            .select(WorkflowEventRow::as_select())
            .load::<WorkflowEventRow>(self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}

// ── Status conversion helpers ────────────────────────────────────────

const fn instance_status_to_db(status: WorkflowInstanceStatus) -> &'static str {
    match status {
        WorkflowInstanceStatus::Pending => "pending",
        WorkflowInstanceStatus::Active => "active",
        WorkflowInstanceStatus::Waiting => "waiting",
        WorkflowInstanceStatus::Succeeded => "succeeded",
        WorkflowInstanceStatus::Failed => "failed",
        WorkflowInstanceStatus::Cancelled => "cancelled",
        WorkflowInstanceStatus::Expired => "expired",
    }
}

fn parse_instance_status(
    value: &str,
    row: Ulid,
) -> Result<WorkflowInstanceStatus, DatabaseInconsistencyError> {
    match value {
        "pending" => Ok(WorkflowInstanceStatus::Pending),
        "active" => Ok(WorkflowInstanceStatus::Active),
        "waiting" => Ok(WorkflowInstanceStatus::Waiting),
        "succeeded" => Ok(WorkflowInstanceStatus::Succeeded),
        "failed" => Ok(WorkflowInstanceStatus::Failed),
        "cancelled" => Ok(WorkflowInstanceStatus::Cancelled),
        "expired" => Ok(WorkflowInstanceStatus::Expired),
        _ => Err(DatabaseInconsistencyError::on("workflow_instances")
            .column("status")
            .row(row)),
    }
}

const fn step_status_to_db(status: WorkflowStepStatus) -> &'static str {
    match status {
        WorkflowStepStatus::Pending => "pending",
        WorkflowStepStatus::Scheduled => "scheduled",
        WorkflowStepStatus::Running => "running",
        WorkflowStepStatus::Waiting => "waiting",
        WorkflowStepStatus::Succeeded => "succeeded",
        WorkflowStepStatus::Failed => "failed",
        WorkflowStepStatus::Cancelled => "cancelled",
        WorkflowStepStatus::Skipped => "skipped",
    }
}

fn parse_step_status(
    value: &str,
    row: Ulid,
) -> Result<WorkflowStepStatus, DatabaseInconsistencyError> {
    match value {
        "pending" => Ok(WorkflowStepStatus::Pending),
        "scheduled" => Ok(WorkflowStepStatus::Scheduled),
        "running" => Ok(WorkflowStepStatus::Running),
        "waiting" => Ok(WorkflowStepStatus::Waiting),
        "succeeded" => Ok(WorkflowStepStatus::Succeeded),
        "failed" => Ok(WorkflowStepStatus::Failed),
        "cancelled" => Ok(WorkflowStepStatus::Cancelled),
        "skipped" => Ok(WorkflowStepStatus::Skipped),
        _ => Err(DatabaseInconsistencyError::on("workflow_steps")
            .column("status")
            .row(row)),
    }
}

const fn event_kind_to_db(kind: WorkflowEventKind) -> &'static str {
    match kind {
        WorkflowEventKind::InstanceCreated => "instance_created",
        WorkflowEventKind::InstanceActivated => "instance_activated",
        WorkflowEventKind::StepScheduled => "step_scheduled",
        WorkflowEventKind::StepStarted => "step_started",
        WorkflowEventKind::StepSucceeded => "step_succeeded",
        WorkflowEventKind::StepFailed => "step_failed",
        WorkflowEventKind::StepSkipped => "step_skipped",
        WorkflowEventKind::WaitingEntered => "waiting_entered",
        WorkflowEventKind::WaitingResolved => "waiting_resolved",
        WorkflowEventKind::DeadlineScheduled => "deadline_scheduled",
        WorkflowEventKind::DeadlineSatisfied => "deadline_satisfied",
        WorkflowEventKind::DeadlineMissed => "deadline_missed",
        WorkflowEventKind::InstanceSucceeded => "instance_succeeded",
        WorkflowEventKind::InstanceFailed => "instance_failed",
        WorkflowEventKind::InstanceCancelled => "instance_cancelled",
        WorkflowEventKind::InstanceExpired => "instance_expired",
    }
}

fn parse_event_kind(
    value: &str,
    row: Ulid,
) -> Result<WorkflowEventKind, DatabaseInconsistencyError> {
    match value {
        "instance_created" => Ok(WorkflowEventKind::InstanceCreated),
        "instance_activated" => Ok(WorkflowEventKind::InstanceActivated),
        "step_scheduled" => Ok(WorkflowEventKind::StepScheduled),
        "step_started" => Ok(WorkflowEventKind::StepStarted),
        "step_succeeded" => Ok(WorkflowEventKind::StepSucceeded),
        "step_failed" => Ok(WorkflowEventKind::StepFailed),
        "step_skipped" => Ok(WorkflowEventKind::StepSkipped),
        "waiting_entered" => Ok(WorkflowEventKind::WaitingEntered),
        "waiting_resolved" => Ok(WorkflowEventKind::WaitingResolved),
        "deadline_scheduled" => Ok(WorkflowEventKind::DeadlineScheduled),
        "deadline_satisfied" => Ok(WorkflowEventKind::DeadlineSatisfied),
        "deadline_missed" => Ok(WorkflowEventKind::DeadlineMissed),
        "instance_succeeded" => Ok(WorkflowEventKind::InstanceSucceeded),
        "instance_failed" => Ok(WorkflowEventKind::InstanceFailed),
        "instance_cancelled" => Ok(WorkflowEventKind::InstanceCancelled),
        "instance_expired" => Ok(WorkflowEventKind::InstanceExpired),
        _ => Err(DatabaseInconsistencyError::on("workflow_events")
            .column("kind")
            .row(row)),
    }
}

fn deserialize_json<T>(
    table: &'static str,
    column: &'static str,
    row: Ulid,
    value: serde_json::Value,
) -> Result<T, DatabaseInconsistencyError>
where
    T: DeserializeOwned,
{
    serde_json::from_value(value).map_err(|e| {
        DatabaseInconsistencyError::on(table)
            .column(column)
            .row(row)
            .source(e)
    })
}
