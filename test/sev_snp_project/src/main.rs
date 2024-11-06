// This code must be run in the provided VM. It will not work on a normal machine.
use sev::firmware::guest::*;

use openssl::{
    ecdsa::EcdsaSig,
    pkey::{PKey, Public},
    sha::Sha384,
    x509::X509,
};
use sev::certs::snp::{ca, Certificate, Chain, Verifiable};
use reqwest::blocking::get;
use reqwest::blocking::Response;
use sev::firmware::host::TcbVersion;
use std::error::Error;

const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
const KDS_VCEK: &str = "/vcek/v1";
const KDS_CERT_CHAIN: &str = "cert_chain";

/// Requests the certificate-chain (AMD ASK + AMD ARK)
/// These may be used to verify the downloaded VCEK is authentic.
pub fn request_cert_chain(sev_prod_name: &str) -> Result<ca::Chain, Box<dyn Error>> {
    // Should make -> https://kdsintf.amd.com/vcek/v1/{SEV_PROD_NAME}/cert_chain
    let url: String = format!("{KDS_CERT_SITE}{KDS_VCEK}/{sev_prod_name}/{KDS_CERT_CHAIN}");
    println!("Requesting AMD certificate-chain from: {url}");
    let rsp: Response = get(&url)?;
    if !rsp.status().is_success() {
        eprintln!("Failed to get the AMD certificate-chain!");
    }
    dbg!(&rsp);
    let body: Vec<u8> = rsp.bytes()?.to_vec();
    let chain: Vec<X509> = X509::stack_from_pem(&body)?;
    dbg!(&chain);
    // Create a ca chain with ark and ask
    let ca_chain: ca::Chain = ca::Chain::from_pem(&chain[1].to_pem()?, &chain[0].to_pem()?)?;
    Ok(ca_chain)
}

/// Requests the VCEK for the specified chip and TCP
pub fn request_vcek(sev_prod_name: &str, chip_id: [u8; 64], reported_tcb: TcbVersion) -> Result<X509, Box<dyn Error>> {
    let hw_id: String = hex::encode(&chip_id);
    let url: String = format!(
        "{KDS_CERT_SITE}{KDS_VCEK}/{sev_prod_name}/{hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
        reported_tcb.bootloader,
        reported_tcb.tee,
        reported_tcb.snp,
        reported_tcb.microcode
    );
    println!("Requesting VCEK from: {url}\n");
    let rsp_bytes = get(&url)?.bytes()?.to_vec();
    Ok(X509::from_der(&rsp_bytes)?)
}

fn main() -> Result<(), Box<dyn Error>> {
    // Example string to be converted
    let input_string = "AMD is extremely awesome! We make the best CPUs! AMD Rocks!!!!!!";

    // Convert the string to a byte array
    let unique_data: [u8; 64] = {
        let mut data = [0u8; 64];
        let bytes = input_string.as_bytes();
        let len = bytes.len().min(64);
        data[..len].copy_from_slice(&bytes[..len]);
        data
    };
    // Create a message version (OPTIONAL)
    let msg_ver: u8 = 1;

    // Set the VMPL level (OPTIONAL).
    let vmpl = 1;
    // Open a connection to the firmware.
    let mut fw: Firmware = Firmware::open()?;

    // Request a standard attestation report.
    let attestation_report: AttestationReport = fw.get_report(Some(msg_ver), Some(unique_data), Some(vmpl))?;
    let _ext_attestation_report = fw.get_ext_report(Some(msg_ver), Some(unique_data), Some(vmpl))?;

    let request: DerivedKey = DerivedKey::new(false, GuestFieldSelect(1), 0, 0, 0);
    let _derived_key = fw.get_derived_key(None, request)?;

    //dbg!(attestation_report);
    let ca_chain: ca::Chain = request_cert_chain("Milan")?;

    ca_chain.verify()?;
    println!("Verified the AMD certificate-chain!");
    // chip_id and reported_tcb should be pulled from the host machine,
    // or an attestation report. 
    dbg!(&attestation_report.chip_id);
    dbg!(&attestation_report.reported_tcb);
    let vcek: Certificate = request_vcek(
        "Milan",
        attestation_report.chip_id,
        attestation_report.reported_tcb
    )?.into();


    // Create a full-chain with the certificates:
    let cert_chain = Chain{ca: ca_chain, vek: vcek};
    //Now you can simply verify the whole chain in one command.
    cert_chain.verify()?;

    // //Or you can verify each certificate individually
    // let ark = cert_chain.ca.ark;
    // let ask = cert_chain.ca.ask;
    // if (&ark,&ark).verify().unwrap() {
    //  println!("The AMD ARK was self-signed...");
    //  if (&ark,&ask).verify().unwrap() {
    //  iprintln!("The AMD ASK was signed by the AMD ARK...");
    //  if (&ask,&vcek).verify().unwrap() {
    //  println!("The VCEK was signed by the AMD ASK...");
    // } else {
    //  eprintln!("The VCEK was not signed by the AMD ASK!");
    // }} else {
    //     eprintln!("The AMD ASK was not signed by the AMD ARK!");
    //     }
    //    } else {
    //     eprintln!("The AMD ARK is not self-signed!");
    //    }
    // }
    Ok(())
}
