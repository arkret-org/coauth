use async_trait::async_trait;
use chrono::{DateTime, Utc};
use coauth_data::{
    Clock, WorkflowActor, WorkflowAssignee, WorkflowEvent, WorkflowEventKind, WorkflowInstance,
    WorkflowInstanceStatus, WorkflowStep, WorkflowStepStatus, WorkflowSubject,
};
use rand_core::RngCore;
use serde_json::Value;
use ulid::Ulid;

use crate::repository_impl;

/// Parameters used when creating a new workflow instance.
#[derive(Debug, Clone)]
pub struct NewWorkflowInstance {
    workflow_key: String,
    subject: WorkflowSubject,
    trigger: WorkflowActor,
    input: Value,
    correlation_key: Option<String>,
    expires_at: Option<DateTime<Utc>>,
}

impl NewWorkflowInstance {
    /// Create a new workflow instance draft.
    #[must_use]
    pub fn new(
        workflow_key: impl Into<String>,
        subject: WorkflowSubject,
        trigger: WorkflowActor,
        input: Value,
    ) -> Self {
        Self {
            workflow_key: workflow_key.into(),
            subject,
            trigger,
            input,
            correlation_key: None,
            expires_at: None,
        }
    }

    /// Attach a cross-system correlation key.
    #[must_use]
    pub fn with_correlation_key(mut self, correlation_key: impl Into<String>) -> Self {
        self.correlation_key = Some(correlation_key.into());
        self
    }

    /// Set an automatic expiration time for the workflow.
    #[must_use]
    pub fn expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// The application-defined workflow kind.
    #[must_use]
    pub fn workflow_key(&self) -> &str {
        &self.workflow_key
    }

    /// The business subject attached to this workflow.
    #[must_use]
    pub fn subject(&self) -> &WorkflowSubject {
        &self.subject
    }

    /// The actor that created or resumed this workflow.
    #[must_use]
    pub fn trigger(&self) -> &WorkflowActor {
        &self.trigger
    }

    /// The immutable structured input captured at workflow creation.
    #[must_use]
    pub fn input(&self) -> &Value {
        &self.input
    }

    /// The cross-system correlation key, if any.
    #[must_use]
    pub fn correlation_key(&self) -> Option<&str> {
        self.correlation_key.as_deref()
    }

    /// The automatic expiration time, if any.
    #[must_use]
    pub fn expiration(&self) -> Option<DateTime<Utc>> {
        self.expires_at
    }
}

/// Parameters used when creating a new workflow step.
#[derive(Debug, Clone)]
pub struct NewWorkflowStep {
    step_key: String,
    sequence: u32,
    assignee: Option<WorkflowAssignee>,
    input: Value,
}

impl NewWorkflowStep {
    /// Create a new workflow step draft.
    #[must_use]
    pub fn new(step_key: impl Into<String>, sequence: u32, input: Value) -> Self {
        Self {
            step_key: step_key.into(),
            sequence,
            assignee: None,
            input,
        }
    }

    /// Assign an execution owner for this step.
    #[must_use]
    pub fn with_assignee(mut self, assignee: WorkflowAssignee) -> Self {
        self.assignee = Some(assignee);
        self
    }

    /// The application-defined step key.
    #[must_use]
    pub fn step_key(&self) -> &str {
        &self.step_key
    }

    /// The stable execution order within the workflow.
    #[must_use]
    pub fn sequence(&self) -> u32 {
        self.sequence
    }

    /// The execution owner for this step, if any.
    #[must_use]
    pub fn assignee(&self) -> Option<&WorkflowAssignee> {
        self.assignee.as_ref()
    }

    /// The immutable structured input captured at scheduling time.
    #[must_use]
    pub fn input(&self) -> &Value {
        &self.input
    }
}

/// Parameters used when appending a workflow event.
#[derive(Debug, Clone)]
pub struct NewWorkflowEvent {
    kind: WorkflowEventKind,
    actor: WorkflowActor,
    payload: Value,
    workflow_step_id: Option<Ulid>,
}

impl NewWorkflowEvent {
    /// Create a new workflow event draft.
    #[must_use]
    pub fn new(kind: WorkflowEventKind, actor: WorkflowActor, payload: Value) -> Self {
        Self {
            kind,
            actor,
            payload,
            workflow_step_id: None,
        }
    }

    /// Associate the event with a specific workflow step.
    #[must_use]
    pub fn for_step(mut self, workflow_step_id: Ulid) -> Self {
        self.workflow_step_id = Some(workflow_step_id);
        self
    }

    /// The event kind.
    #[must_use]
    pub fn kind(&self) -> WorkflowEventKind {
        self.kind
    }

    /// The actor that triggered the event.
    #[must_use]
    pub fn actor(&self) -> &WorkflowActor {
        &self.actor
    }

    /// The structured event payload.
    #[must_use]
    pub fn payload(&self) -> &Value {
        &self.payload
    }

    /// The related step identifier, if any.
    #[must_use]
    pub fn workflow_step_id(&self) -> Option<Ulid> {
        self.workflow_step_id
    }
}

/// Repository for persisted workflow instances, steps, and events.
#[async_trait]
pub trait WorkflowRepository: Send + Sync {
    /// The error type returned by the repository.
    type Error;

    /// Look up a workflow instance by ID.
    async fn lookup_instance(&mut self, id: Ulid) -> Result<Option<WorkflowInstance>, Self::Error>;

    /// Create a new workflow instance.
    async fn add_instance(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewWorkflowInstance,
    ) -> Result<WorkflowInstance, Self::Error>;

    /// Update the lifecycle status of an existing workflow instance.
    async fn set_instance_status(
        &mut self,
        clock: &dyn Clock,
        workflow_instance: WorkflowInstance,
        status: WorkflowInstanceStatus,
    ) -> Result<WorkflowInstance, Self::Error>;

    /// Look up a workflow step by ID.
    async fn lookup_step(&mut self, id: Ulid) -> Result<Option<WorkflowStep>, Self::Error>;

    /// List all steps belonging to a workflow instance.
    async fn list_steps(
        &mut self,
        workflow_instance: &WorkflowInstance,
    ) -> Result<Vec<WorkflowStep>, Self::Error>;

    /// Create a new step within a workflow instance.
    async fn add_step(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        workflow_instance: &WorkflowInstance,
        params: NewWorkflowStep,
    ) -> Result<WorkflowStep, Self::Error>;

    /// Update the lifecycle status of an existing workflow step.
    async fn set_step_status(
        &mut self,
        clock: &dyn Clock,
        workflow_step: WorkflowStep,
        status: WorkflowStepStatus,
    ) -> Result<WorkflowStep, Self::Error>;

    /// Append an immutable workflow event.
    async fn append_event(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        workflow_instance: &WorkflowInstance,
        workflow_step: Option<&WorkflowStep>,
        params: NewWorkflowEvent,
    ) -> Result<WorkflowEvent, Self::Error>;

    /// List events for a workflow instance.
    async fn list_events(
        &mut self,
        workflow_instance: &WorkflowInstance,
    ) -> Result<Vec<WorkflowEvent>, Self::Error>;
}

repository_impl!(WorkflowRepository:
    async fn lookup_instance(
        &mut self,
        id: Ulid,
    ) -> Result<Option<WorkflowInstance>, Self::Error>;
    async fn add_instance(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        params: NewWorkflowInstance,
    ) -> Result<WorkflowInstance, Self::Error>;
    async fn set_instance_status(
        &mut self,
        clock: &dyn Clock,
        workflow_instance: WorkflowInstance,
        status: WorkflowInstanceStatus,
    ) -> Result<WorkflowInstance, Self::Error>;
    async fn lookup_step(
        &mut self,
        id: Ulid,
    ) -> Result<Option<WorkflowStep>, Self::Error>;
    async fn list_steps(
        &mut self,
        workflow_instance: &WorkflowInstance,
    ) -> Result<Vec<WorkflowStep>, Self::Error>;
    async fn add_step(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        workflow_instance: &WorkflowInstance,
        params: NewWorkflowStep,
    ) -> Result<WorkflowStep, Self::Error>;
    async fn set_step_status(
        &mut self,
        clock: &dyn Clock,
        workflow_step: WorkflowStep,
        status: WorkflowStepStatus,
    ) -> Result<WorkflowStep, Self::Error>;
    async fn append_event(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        workflow_instance: &WorkflowInstance,
        workflow_step: Option<&WorkflowStep>,
        params: NewWorkflowEvent,
    ) -> Result<WorkflowEvent, Self::Error>;
    async fn list_events(
        &mut self,
        workflow_instance: &WorkflowInstance,
    ) -> Result<Vec<WorkflowEvent>, Self::Error>;
);
