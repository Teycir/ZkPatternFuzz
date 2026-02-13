//! Backend integrations for ZkPatternFuzz.

pub mod registry;
pub mod fixture;

#[cfg(feature = "circom")]
pub mod circom;
#[cfg(feature = "noir")]
pub mod noir;
#[cfg(feature = "halo2")]
pub mod halo2;
#[cfg(feature = "cairo")]
pub mod cairo;

pub use registry::{BackendConfig, BackendError, BackendProvider, BackendRegistry};
pub use fixture::{
    create_collision_fixture, create_underconstrained_fixture, FixtureCircuitExecutor,
};

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

    /// Get the scalar-field modulus for this circuit's arithmetic as a 32-byte
    /// big-endian array.
    ///
    /// Implementations must return the correct prime for their proving system.
    /// The default falls back to the BN254 scalar-field modulus for backwards
    /// compatibility, but every concrete backend should override this.
    fn field_modulus(&self) -> [u8; 32] {
        // BN254 scalar field – default for backwards compat
        let mut modulus = [0u8; 32];
        let hex_str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
        if let Ok(decoded) = hex::decode(hex_str) {
            modulus.copy_from_slice(&decoded);
        }
        modulus
    }

    /// Human-readable field-prime name (e.g. "bn254", "pasta", "bls12-381",
    /// "stark252").  Used for logging and evidence metadata.
    fn field_name(&self) -> &str {
        "bn254"
    }
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
        }
    }
}
