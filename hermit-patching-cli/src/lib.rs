/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Statically selected physical frontends for the one shared Hermit app.
//! e9patch is preprocessing followed by the existing ptrace runtime.

pub use hermit::instruction_map;
pub use hermit::{Context, Error, HermitData};

mod artifact_elf;
mod core_engine_artifact;
pub mod e9patch;
mod e9patch_adapter;
mod sabre_adapter;
mod sabre_artifacts;
mod sabre_bootstrap;
mod sabre_loader;
mod sabre_physical;
mod sabre_ptrace;
mod sabre_strace;

pub use e9patch_adapter::E9patchAdapter;
pub use sabre_adapter::SabreAdapter;
pub use sabre_artifacts::SabreArtifacts;
