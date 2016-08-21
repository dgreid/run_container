#![feature(plugin, custom_derive)]
#![plugin(serde_macros)]

mod oci_config;

#[cfg(test)]
mod tests {
    extern crate serde;
    extern crate serde_json;

    use self::serde_json::{Map, Value};

    #[test]
    fn json_test() {
        let mut map = Map::new();
        map.insert("x".to_string(), 1.0);
        map.insert("y".to_string(), 2.0);

        let s = serde_json::to_string(&map).unwrap();
        assert_eq!(s, "{\"x\":1.0,\"y\":2.0}");

        let deserialized_map: Map<String, f64> = serde_json::from_str(&s).unwrap();
        assert_eq!(map, deserialized_map);

        let data: Value = serde_json::from_str("{\"foo\": 13, \"bar\": \"baz\"}").unwrap();

        assert_eq!(data.find("foo"), Some(&Value::U64(13)));
        assert_eq!(data.find("bar"), Some(&Value::String("baz".to_string())));
    }

    #[derive(Serialize, Deserialize)]
    struct TestPoint {
	x: i32,
	y: i32,
    }

    #[test]
    fn json_serialize() {
	let test_point_str = r#"
	    {
		"x": 3,
		"y": 5
	    }
	"#;
	let deserialized: TestPoint = serde_json::from_str(test_point_str).unwrap();
	assert_eq!(deserialized.x, 3);

	let test_point: TestPoint = TestPoint {x: 5, y: 4};
	println!("serialized = {}", serde_json::to_string(&test_point).unwrap());
    }
}
