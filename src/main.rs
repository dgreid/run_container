mod container;

use container::Container;

fn main() {
    let c = Container::new("asdf");
    println!("{}", c.name());
}
