extern crate serde;
extern crate serde_json;

#[derive(Serialize, Deserialize)]
pub struct OciConfig {
    #[serde(rename="ociVersion")]
    oci_version: String,
}

#[cfg(test)]
mod tests {
    extern crate serde;
    extern crate serde_json;

    use super::OciConfig;

    #[test]
    fn json_test() {
        let basic_json_str = r#"
            {
                "ociVersion": "1.0.0-rc1"
            }
        "#;

        let basic_config: OciConfig = serde_json::from_str(basic_json_str).unwrap();
        assert_eq!(basic_config.oci_version, "1.0.0-rc1");
    }
}
