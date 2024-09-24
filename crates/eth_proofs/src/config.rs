pub trait ChainConfig {
    const ID: u64;
    const DENEB_INIT_SLOT: u64;
    const CAPELLA_INIT_SLOT: u64;
    const FIRST_POS_SLOT: u64;
    const FIRST_POS_SLOT_TIMESTAMP: u64;
}

pub struct Mainnet;

impl ChainConfig for Mainnet {
    const ID: u64 = 1;
    const DENEB_INIT_SLOT: u64 = 8626176;
    const CAPELLA_INIT_SLOT: u64 = 6209536;

    // https://eth2book.info/capella/part3/config/configuration/#:~:text=Thus%2C%20the%20Bellatrix,was%20not%20needed.
    const FIRST_POS_SLOT: u64 = 4700013;
    const FIRST_POS_SLOT_TIMESTAMP: u64 = 1663224179;
}
