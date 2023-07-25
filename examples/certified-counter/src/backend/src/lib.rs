use ic_cdk::export::candid::CandidType;
use ic_cdk::*;
use ic_certified_map::*;
use serde::Serialize;
use std::cell::*;

thread_local! {
    static COUNTER: Cell<u32> = Cell::new(0);
    static TREE: RefCell<RbTree<&'static str, Vec<u8>>> = RefCell::new(RbTree::new());
}

#[update]
fn inc_count() {
    let count = COUNTER.with(|counter| {
        let count = counter.get() + 1;
        counter.set(count);
        count
    });

    TREE.with(|tree| {
        let mut tree = tree.borrow_mut();
        tree.insert(
            "count",
            hex::decode(sha256::digest(&count.to_be_bytes())).unwrap(),
        );

        ic_cdk::api::set_certified_data(&tree.root_hash());
    })
}

#[derive(CandidType)]
struct CertifiedCounter {
    count: u32,
    certificate: Vec<u8>,
    witness: Vec<u8>,
}

fn get_count_witness() -> anyhow::Result<Vec<u8>> {
    TREE.with(|tree| {
        let tree = tree.borrow();
        let mut witness = vec![];
        let mut witness_serializer = serde_cbor::Serializer::new(&mut witness);

        witness_serializer.self_describe()?;

        tree.witness(b"count")
            .serialize(&mut witness_serializer)
            .unwrap();

        Ok(witness)
    })
}

#[query]
fn get_count() -> CertifiedCounter {
    let certificate = ic_cdk::api::data_certificate().expect("No data certificate available");

    let witness = match get_count_witness() {
        Ok(tree) => tree,
        Err(err) => {
            ic_cdk::trap(&format!("Error getting count witness: {:?}", err));
        }
    };

    let count = COUNTER.with(|counter| counter.get());

    CertifiedCounter {
        count,
        certificate,
        witness,
    }
}