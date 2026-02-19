use fake::faker::internet::en::{SafeEmail, IPv4};
use fake::faker::name::en::Name;
use fake::faker::phone_number::en::PhoneNumber;
use fake::Fake;

pub fn get_fake_name() -> String {
    Name().fake()
}

pub fn get_fake_email() -> String {
    SafeEmail().fake()
}

pub fn get_fake_phone() -> String {
    PhoneNumber().fake()
}

pub fn get_fake_ip() -> String {
    IPv4().fake()
}
