//! Host-side implementation and registration.
pub use crate::sequence_builder;

use crate::{
    INLINE_OPCODE, P256_DIVQ_FUNCT3, P256_DIVQ_NAME, P256_DIVR_FUNCT3, P256_DIVR_NAME,
    P256_FUNCT7, P256_MULQ_FUNCT3, P256_MULQ_NAME, P256_MULR_FUNCT3, P256_MULR_NAME,
    P256_SQUAREQ_FUNCT3, P256_SQUAREQ_NAME, P256_SQUARER_FUNCT3, P256_SQUARER_NAME,
};
use tracer::register_inline;

use tracer::utils::inline_sequence_writer::{
    write_inline_trace, AppendMode, InlineDescriptor, SequenceInputs,
};

pub fn init_inlines() -> Result<(), String> {
    register_inline(
        INLINE_OPCODE,
        P256_MULQ_FUNCT3,
        P256_FUNCT7,
        P256_MULQ_NAME,
        std::boxed::Box::new(sequence_builder::p256_mulq_sequence_builder),
        Some(std::boxed::Box::new(
            sequence_builder::p256_mulq_advice,
        )),
    )?;
    register_inline(
        INLINE_OPCODE,
        P256_SQUAREQ_FUNCT3,
        P256_FUNCT7,
        P256_SQUAREQ_NAME,
        std::boxed::Box::new(sequence_builder::p256_squareq_sequence_builder),
        Some(std::boxed::Box::new(
            sequence_builder::p256_squareq_advice,
        )),
    )?;
    register_inline(
        INLINE_OPCODE,
        P256_DIVQ_FUNCT3,
        P256_FUNCT7,
        P256_DIVQ_NAME,
        std::boxed::Box::new(sequence_builder::p256_divq_sequence_builder),
        Some(std::boxed::Box::new(
            sequence_builder::p256_divq_advice,
        )),
    )?;
    register_inline(
        INLINE_OPCODE,
        P256_MULR_FUNCT3,
        P256_FUNCT7,
        P256_MULR_NAME,
        std::boxed::Box::new(sequence_builder::p256_mulr_sequence_builder),
        Some(std::boxed::Box::new(
            sequence_builder::p256_mulr_advice,
        )),
    )?;
    register_inline(
        INLINE_OPCODE,
        P256_SQUARER_FUNCT3,
        P256_FUNCT7,
        P256_SQUARER_NAME,
        std::boxed::Box::new(sequence_builder::p256_squarer_sequence_builder),
        Some(std::boxed::Box::new(
            sequence_builder::p256_squarer_advice,
        )),
    )?;
    register_inline(
        INLINE_OPCODE,
        P256_DIVR_FUNCT3,
        P256_FUNCT7,
        P256_DIVR_NAME,
        std::boxed::Box::new(sequence_builder::p256_divr_sequence_builder),
        Some(std::boxed::Box::new(
            sequence_builder::p256_divr_advice,
        )),
    )?;
    Ok(())
}

pub fn store_inlines() -> Result<(), String> {
    let inline_info = InlineDescriptor::new(
        P256_MULQ_NAME.to_string(),
        INLINE_OPCODE,
        P256_MULQ_FUNCT3,
        P256_FUNCT7,
    );
    let inputs = SequenceInputs::default();
    let instructions =
        sequence_builder::p256_mulq_sequence_builder((&inputs).into(), (&inputs).into());
    write_inline_trace(
        "p256_trace.joltinline",
        &inline_info,
        &inputs,
        &instructions,
        AppendMode::Overwrite,
    )
    .map_err(|e| e.to_string())?;
    // Append p256 squareq inline trace
    let inline_info = InlineDescriptor::new(
        P256_SQUAREQ_NAME.to_string(),
        INLINE_OPCODE,
        P256_SQUAREQ_FUNCT3,
        P256_FUNCT7,
    );
    let inputs = SequenceInputs::default();
    let instructions =
        sequence_builder::p256_squareq_sequence_builder((&inputs).into(), (&inputs).into());
    write_inline_trace(
        "p256_trace.joltinline",
        &inline_info,
        &inputs,
        &instructions,
        AppendMode::Append,
    )
    .map_err(|e| e.to_string())?;
    // Append p256 divq inline trace
    let inline_info = InlineDescriptor::new(
        P256_DIVQ_NAME.to_string(),
        INLINE_OPCODE,
        P256_DIVQ_FUNCT3,
        P256_FUNCT7,
    );
    let inputs = SequenceInputs::default();
    let instructions =
        sequence_builder::p256_divq_sequence_builder((&inputs).into(), (&inputs).into());
    write_inline_trace(
        "p256_trace.joltinline",
        &inline_info,
        &inputs,
        &instructions,
        AppendMode::Append,
    )
    .map_err(|e| e.to_string())?;
    // Append p256 mulr inline trace
    let inline_info = InlineDescriptor::new(
        P256_MULR_NAME.to_string(),
        INLINE_OPCODE,
        P256_MULR_FUNCT3,
        P256_FUNCT7,
    );
    let inputs = SequenceInputs::default();
    let instructions =
        sequence_builder::p256_mulr_sequence_builder((&inputs).into(), (&inputs).into());
    write_inline_trace(
        "p256_trace.joltinline",
        &inline_info,
        &inputs,
        &instructions,
        AppendMode::Append,
    )
    .map_err(|e| e.to_string())?;
    // Append p256 squarer inline trace
    let inline_info = InlineDescriptor::new(
        P256_SQUARER_NAME.to_string(),
        INLINE_OPCODE,
        P256_SQUARER_FUNCT3,
        P256_FUNCT7,
    );
    let inputs = SequenceInputs::default();
    let instructions =
        sequence_builder::p256_squarer_sequence_builder((&inputs).into(), (&inputs).into());
    write_inline_trace(
        "p256_trace.joltinline",
        &inline_info,
        &inputs,
        &instructions,
        AppendMode::Append,
    )
    .map_err(|e| e.to_string())?;
    // Append p256 divr inline trace
    let inline_info = InlineDescriptor::new(
        P256_DIVR_NAME.to_string(),
        INLINE_OPCODE,
        P256_DIVR_FUNCT3,
        P256_FUNCT7,
    );
    let inputs = SequenceInputs::default();
    let instructions =
        sequence_builder::p256_divr_sequence_builder((&inputs).into(), (&inputs).into());
    write_inline_trace(
        "p256_trace.joltinline",
        &inline_info,
        &inputs,
        &instructions,
        AppendMode::Append,
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[ctor::ctor]
fn auto_register() {
    if let Err(e) = init_inlines() {
        tracing::error!("Failed to register p256 inlines: {e}");
    }

    if std::env::var("STORE_INLINE").unwrap_or_default() == "true" {
        if let Err(e) = store_inlines() {
            tracing::error!("Failed to store p256 inline traces: {e}");
        }
    }
}
