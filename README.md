# CO.DELTA △ - frontend
Built on the [Internet Computer ∞](https://internetcomputer.org/) 

The core backend logic is maintained in a [separate repo](https://github.com/aodl/CO.DELTA) (fund dispersal and neuron controller canister).

This repo is a fork of DFINITY's verifiable http response repository. We've opted to use a trimmed down version for serving up frontend assets to improve verifiability and the consensus workflow (as simple as building locally and verifying the hash). The standard asset canister was used previously, but that approach does not embedded web assets in the module WASM (they're uploaded as separate staging and then commit steps). That complicated the verification and consensus workflow - hence the motivation for refactoring and moving the frontend logic into this repo. See https://github.com/aodl/CO.DELTA/issues/13 for further context.

![codelta.svg](https://wtjj7-cyaaa-aaaar-qaozq-cai.icp0.io/codelta.svg)

We're a verifiably decentralised **co**llective who review IC **delta**s (changes applied by [NNS proposals](https://dashboard.internetcomputer.org/governance?s=100&topic=TOPIC_API_BOUNDARY_NODE_MANAGEMENT|TOPIC_APPLICATION_CANISTER_MANAGEMENT|TOPIC_GOVERNANCE|TOPIC_IC_OS_VERSION_DEPLOYMENT|TOPIC_IC_OS_VERSION_ELECTION|TOPIC_KYC|TOPIC_NETWORK_ECONOMICS|TOPIC_NODE_ADMIN|TOPIC_NODE_PROVIDER_REWARDS|TOPIC_PARTICIPANT_MANAGEMENT|TOPIC_PROTOCOL_CANISTER_MANAGEMENT|TOPIC_SERVICE_NERVOUS_SYSTEM_MANAGEMENT|TOPIC_SNS_AND_COMMUNITY_FUND|TOPIC_SUBNET_MANAGEMENT|TOPIC_SUBNET_RENTAL|TOPIC_SYSTEM_CANISTER_MANAGEMENT)). We follow a common **code**:

- **L**ook: We observe the details and context of NNS proposals
- **T**est: We test and verify the claims made by those proposals
- **A**utomate: We automate as much as possible by building increasingly sophisticated tools that streamline and strengthen the reviewal process.

Every vote cast by **CO.DELTA** is the result of consensus among diligent, skilled and experienced team members acting independently. The [CO.DELTA neuron](https://dashboard.internetcomputer.org/neuron/33138099823745946) follows the vote of [D-QUORUM](https://dashboard.internetcomputer.org/neuron/4713806069430754115) on NNS topics that the CO.DELTA team does not handle directly. You can therefore follow CO.DELTA on all NNS topics and rely on a high quality vote.
