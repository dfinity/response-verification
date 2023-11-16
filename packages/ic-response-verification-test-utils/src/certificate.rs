use crate::{base64_encode, hex_decode};
use ic_certification::{fork, labeled, leaf, pruned_from_hex, Certificate, Delegation, HashTree};
use ic_types::CanisterId;
use std::str::FromStr;

pub fn create_canister_id(canister_id: &str) -> CanisterId {
    CanisterId::from_str(canister_id).unwrap()
}

pub fn create_certificate_header(certificate: &[u8], tree: &[u8]) -> String {
    let certificate = base64_encode(certificate);
    let tree = base64_encode(tree);

    format!("certificate=:{}:, tree=:{}:", certificate, tree)
}

pub fn create_versioned_certificate_header(
    certificate: &[u8],
    tree: &[u8],
    expr_path: &[u8],
    version: u8,
) -> String {
    let certificate = base64_encode(certificate);
    let tree = base64_encode(tree);
    let expr_path = base64_encode(expr_path);

    format!(
        "certificate=:{}:, tree=:{}:, expr_path=:{}:, version={}",
        certificate, tree, expr_path, version
    )
}

pub struct CreateCertificateOptions<'a> {
    pub time: Option<&'a [u8]>,
    pub canister_id: Option<&'a [u8]>,
    pub certified_data: Option<&'a [u8]>,
}

pub fn create_pruned(data: &str) -> HashTree {
    pruned_from_hex(data).unwrap()
}

pub fn create_certificate(options: Option<CreateCertificateOptions>) -> Certificate {
    let default_time = hex_decode("AFB18DEEB0DA8C9517");
    let time = options
        .as_ref()
        .and_then(|options| options.time)
        .unwrap_or(&default_time);

    let default_canister_id = vec![0, 0, 0, 0, 0, 0, 0, 7, 1, 1];
    let canister_id = options
        .as_ref()
        .and_then(|options| options.canister_id)
        .unwrap_or(&default_canister_id);

    let default_certified_data =
        hex_decode("D9EF7E1964D85B0EA088C9318C913B77152E14C3A6A04277D051514CE62667EE");
    let certified_data = options
        .as_ref()
        .and_then(|options| options.certified_data)
        .unwrap_or(&default_certified_data);

    let tree = fork(
        fork(
            fork(
                labeled("canister",
                      labeled(canister_id,
                            fork(
                                fork(
                                    fork(
                                        labeled(
                                            "certified_data",
                                            leaf(certified_data)
                                        ),
                                        create_pruned("FD5B59459758C8AFECAF7285DA359E4B5ADB945FB86A3C1F0EFD996C21A96938"),
                                    ),
                                    create_pruned("E872843059989FD8F4B051D1C420833575932E70CC6F0E2D0EF93D461DA03F29"),
                                ),
                                create_pruned("281A9DF147D24DD72C6E7CD02D93D7558B092CCE9D73F7E2F9195C5BD0FF5891"),
                            ),
                      ),
                ),
                create_pruned("8001B84283EE0697540FD89F32CE340AF9FDBE7D306A12E349330E06C315E220"),
            ),
            create_pruned("A1AC221030FE0E70538B98FD3632C73161C502559A564E3EDBAFAE970154609E"),
        ),
        fork(
            create_pruned("0B2F12CF83A8A339691C0D39BE38432CEE1A64DA8E3898BB69AFDB6970823C5E"),
            labeled(
                "time",
                leaf(time),
            ),
        ),
    );

    Certificate {
        delegation: None,
        signature: hex::decode("869F2D2BECA39513342CA14E1446EFE3B5E07E70EE2EC3CC79F5680FDDA91C33885067614B56D6D6C0A817D8E5CA0415").unwrap(),
        tree,
    }
}

pub fn create_certificate_delegation() -> Delegation {
    Delegation {
        subnet_id: hex_decode("43DCAF1180DB82FDA708CE3AC7A03A6060ABDE13E9546C60E8CCE65D02"),
        certificate: hex_decode("D9D9F7A26474726565830182045820E752271175EF859A5F69FBF8FAD54EC920C889C4288E3EA9DD7D1E44E6A43E2E83018302467375626E657483018301830182045820267FE55111B56E3C3975532EA3373F7B72E9F82072FE8E607ED34486478A5B39830182045820466A70286CF9ACE9801CA53E22AF6EE059A094FD60498606D484B6854058307D83018301820458208B2F6C15078AE4D3B93470915CA53E373327F37EA74BA1B8177D986BB79B31AE8302581D43DCAF1180DB82FDA708CE3AC7A03A6060ABDE13E9546C60E8CCE65D02830183024F63616E69737465725F72616E67657382035832D9D9F782824A000000000000000701014A00000000000000070101824A000000000210000001014A00000000021FFFFF010183024A7075626C69635F6B657982035885308182301D060D2B0601040182DC7C0503010201060C2B0601040182DC7C050302010361008675B634A43E39726238CFE39C9518BC3E3225CB6F5A8479BFCF2B608FBA6F8524DCB80F35A8AE44B47F262F0A6620D41279F06FE0C53A739FCCA01A48926FE651A3519B5B329FFBECC9F0CB908B098DD3E8845CFB99C56379E049AC465EC8068204582087CD2136474DE6048879C3B70200535651703DC972CACB94FA065FFE2EE6368A820458204A1D76C08E642E3DB6982E6653BE8C736F275A24AC221083430B2D5B441CE754820458202D856BBA7B6C80171CE8E5D121BB7E4450B3565A644D9135E9FE5884281C1FB983024474696D65820349B5D28BDCCB84969417697369676E61747572655830ADEB2390B09EB25DCC7C59B3DA6C2DF63F87ECB39CC2018875FC96A5D5E9DC256AAAC5B003F52BF3EDBB022185ACD447")
    }
}
