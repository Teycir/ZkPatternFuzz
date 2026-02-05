//! Backend integrations for ZkPatternFuzz.

pub mod registry;

#[cfg(feature = "mock")]
pub mod mock;
#[cfg(feature = "circom")]
pub mod circom;
#[cfg(feature = "noir")]
pub mod noir;
#[cfg(feature = "halo2")]
pub mod halo2;
#[cfg(feature = "cairo")]
pub mod cairo;

pub use registry::{BackendConfig, BackendError, BackendProvider, BackendRegistry};

#[cfg(feature = "mock")]
pub use mock::{MockCircuit, MockCircuitExecutor, create_collision_mock, create_underconstrained_mock};
#[cfg(feature = "circom")]
pub use circom::CircomTarget;
#[cfg(feature = "noir")]
pub use noir::NoirTarget;
#[cfg(feature = "halo2")]
pub use halo2::Halo2Target;
#[cfg(feature = "cairo")]
pub use cairo::CairoTarget;

#[cfg(feature = "cairo")]
pub use cairo::analysis as cairo_analysis;
#[cfg(feature = "circom")]
pub use circom::analysis as circom_analysis;
#[cfg(feature = "halo2")]
pub use halo2::analysis as halo2_analysis;
#[cfg(feature = "noir")]
pub use noir::analysis as noir_analysis;

use zk_core::{FieldElement, Framework};

/// Common trait for all ZK circuit targets.
pub trait TargetCircuit: Send + Sync {
    /// Get the framework type.
    fn framework(&self) -> Framework;

    /// Get circuit name.
    fn name(&self) -> &str;

    /// Get number of constraints.
    fn num_constraints(&self) -> usize;

    /// Get number of private inputs.
    fn num_private_inputs(&self) -> usize;

    /// Get number of public inputs.
    fn num_public_inputs(&self) -> usize;

    /// Execute the circuit with given inputs.
    fn execute(&self, inputs: &[FieldElement]) -> anyhow::Result<Vec<FieldElement>>;

    /// Generate a proof for the given witness.
    fn prove(&self, witness: &[FieldElement]) -> anyhow::Result<Vec<u8>>;

    /// Verify a proof with public inputs.
    fn verify(&self, proof: &[u8], public_inputs: &[FieldElement]) -> anyhow::Result<bool>;
}

/// Factory for creating circuit targets.
pub struct TargetFactory;

impl TargetFactory {
    pub fn create(
        framework: Framework,
        circuit_path: &str,
        main_component: &str,
    ) -> anyhow::Result<Box<dyn TargetCircuit>> {
        match framework {
            Framework::Circom => {
                #[cfg(feature = "circom")]
                {
                    Ok(Box::new(CircomTarget::new(circuit_path, main_component)?))
                }
                #[cfg(not(feature = "circom"))]
                {
                    anyhow::bail!("Circom backend not enabled")
                }
            }
            Framework::Noir => {
                #[cfg(feature = "noir")]
                {
                    Ok(Box::new(NoirTarget::new(circuit_path)?))
                }
                #[cfg(not(feature = "noir"))]
                {
                    anyhow::bail!("Noir backend not enabled")
                }
            }
            Framework::Halo2 => {
                #[cfg(feature = "halo2")]
                {
                    Ok(Box::new(Halo2Target::new(circuit_path)?))
                }
                #[cfg(not(feature = "halo2"))]
                {
                    anyhow::bail!("Halo2 backend not enabled")
                }
            }
            Framework::Cairo => {
                #[cfg(feature = "cairo")]
                {
                    Ok(Box::new(CairoTarget::new(circuit_path)?))
                }
                #[cfg(not(feature = "cairo"))]
                {
                    anyhow::bail!("Cairo backend not enabled")
                }
            }
            Framework::Mock => {
                #[cfg(feature = "mock")]
                {
                    Ok(Box::new(MockCircuit::new(main_component, 10, 2)))
                }
                #[cfg(not(feature = "mock"))]
                {
                    anyhow::bail!("Mock backend not enabled")
                }
            }
        }
    }
}
