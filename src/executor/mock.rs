//! Mock executor re-exports from zk-backends.

pub use zk_backends::mock::{
    MockCircuitExecutor, create_collision_mock, create_underconstrained_mock,
};
