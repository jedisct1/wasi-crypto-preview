all: wasi_ephemeral_crypto.md proposal_symmetric.md proposal_signatures.md

wasi_ephemeral_crypto.md: proposal_common.witx proposal_symmetric.witx proposal_signatures.witx
	witx docs proposal_common.witx proposal_symmetric.witx proposal_signatures.witx > wasi_ephemeral_crypto.md

proposal_symmetric.md: proposal_common.witx proposal_symmetric.witx
	witx docs proposal_common.witx proposal_symmetric.witx > proposal_symmetric.md

proposal_signatures.md: proposal_common.witx proposal_signatures.witx
	witx docs proposal_common.witx proposal_signatures.witx > proposal_signatures.md
