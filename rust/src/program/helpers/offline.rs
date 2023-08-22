// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the Aleo SDK library.

// The Aleo SDK library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The Aleo SDK library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the Aleo SDK library. If not, see <https://www.gnu.org/licenses/>.

use super::*;

/// Offline Execution of a single program function
#[derive(Clone)]
pub struct OfflineExecution<N: Network> {
    execution: Execution<N>,
    response: Option<Response<N>>,
    trace: Trace<N>,
    verifying_key: VerifyingKey<N>,
    public_outputs: Option<Vec<Value<N>>>,
}

impl<N: Network> OfflineExecution<N> {
    /// Create a new offline execution of a single function
    pub(crate) fn new(
        execution: Execution<N>,
        response: Option<Response<N>>,
        trace: Trace<N>,
        verifying_key: VerifyingKey<N>,
        public_outputs: Option<Vec<Value<N>>>,
    ) -> Self {
        Self { execution, response, trace, verifying_key, public_outputs }
    }

    /// Get the execution
    pub fn execution(&self) -> &Execution<N> {
        &self.execution
    }

    /// Get the execution id
    pub fn execution_id(&self) -> Result<Field<N>> {
        self.execution.to_execution_id()
    }

    /// Get the execution proof
    pub fn execution_proof(&self) -> Option<&Proof<N>> {
        self.execution.proof()
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey<N> {
        &self.verifying_key
    }

    /// Get the outputs of the execution
    pub fn outputs(&self) -> Option<Vec<Value<N>>> {
        self.response.as_ref().map(|r| r.outputs().to_vec())
    }

    /// Get public outputs
    pub fn public_outputs(&self) -> Option<Vec<Value<N>>> {
        self.public_outputs.clone()
    }

    /// Get the trace of the execution
    pub fn trace(&self) -> &Trace<N> {
        &self.trace
    }

    /// Verify the execution against the given verifier inputs and program verifying key
    #[allow(clippy::type_complexity)]
    pub fn verify_execution(
        execution: &Execution<N>,
        program: &Program<N>,
        function_name: impl TryInto<Identifier<N>>,
        verifying_key: &VerifyingKey<N>,
    ) -> Result<()> {
        let function = function_name.try_into().map_err(|_| anyhow!("Invalid function name"))?;
        let mut process = Process::<N>::load()?;
        process.add_program(program)?;
        process.insert_verifying_key(program.id(), &function, verifying_key.clone())?;
        process.verify_execution(execution)
    }
}
