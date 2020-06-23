/**
 * Defines a bucket which is a special kind of base for a particular app entry.
 *
 * Buckets have an id which must be deterministicly derivable from an entry.
 * This way it is always possible to figure out which bucket an entry must belong to.
 */
use std::boxed::Box;
use hdk::{
		entry_definition::ValidatingEntryType,
		error::ZomeApiResult,
		holochain_core_types::{
				entry::{
						Entry,
						entry_type::AppEntryType,
				},
				dna::entry_types::Sharing,
				link::LinkMatch
		},
};
use hdk::holochain_persistence_api::{
		cas::content::{AddressableContent, Address},
};
use hdk::holochain_json_api::{
		json::{JsonString, RawString},
};

use bs58::{decode};

static BUCKET_LINK_TYPE: [&str; 2] = ["contains_0_", "contains_1_"];

pub struct BucketEntry {
		bucket_for: AppEntryType,
		id: String
}

pub fn bucket_entry_type_for(entry_type: AppEntryType) -> AppEntryType {
		format!("__bucket_for_{}", entry_type.to_string()).into()
}

pub fn bucket_entry_def_for(entry_type: AppEntryType) -> ValidatingEntryType {
		entry!(
				name: bucket_entry_type_for(entry_type.clone()),
				description: "",
				sharing: Sharing::Public,
				validation_package: || {
						hdk::ValidationPackageDefinition::Entry
				},
				validation: |validation_data: hdk::EntryValidationData<RawString>| {
						match validation_data {
								hdk::EntryValidationData::Create{
										entry: _, validation_data: _
								} => Ok(()),
								hdk::EntryValidationData::Modify{
										new_entry: _,
										old_entry: _,
										old_entry_header: _,
										validation_data: _,
								} => Err("Modifying buckets not permitted".into()),
								hdk::EntryValidationData::Delete{
										old_entry: _,
										old_entry_header: _,
										validation_data: _,
								} => Err("Deleting buckets not permitted".into()),

						}
				},
				links: [
						to!(
								entry_type.clone(),
								link_type: BUCKET_LINK_TYPE[0],
								validation_package: || {
										hdk::ValidationPackageDefinition::Entry
								},
								validation: |_validation_data: hdk::LinkValidationData| {
										Ok(())
								}
						),
						to!(
								entry_type.clone(),
								link_type: BUCKET_LINK_TYPE[1],
								validation_package: || {
										hdk::ValidationPackageDefinition::Entry
								},
								validation: |_validation_data: hdk::LinkValidationData| {
										Ok(())
								}
						)
				]
		)
}

impl BucketEntry {
		pub fn entry(&self) -> Entry {
				Entry::App(
						bucket_entry_type_for(self.bucket_for.clone()),
						RawString::from(self.id.clone()).into()
				)
		}
}

pub trait BucketSetStorable {
		fn derive_bucket_id(&self, index: usize) -> String;

		fn derive_bucket_link_name(&self, index: usize) -> JsonString;

		fn get_bucket(&self, entry_type: AppEntryType, index: usize) -> BucketEntry {
				BucketEntry{
						bucket_for: entry_type.to_owned(),
						id: self.derive_bucket_id(index)
				}
		}
}

pub trait BucketIterable {
		fn buckets(index: usize) -> Box<dyn Iterator<Item = String>>;
}

pub fn store<T: Into<JsonString> + BucketSetStorable>( entry_type: AppEntryType, entry_data: T) -> ZomeApiResult<Address> {
		let bucket_address_0 = hdk::commit_entry(&entry_data.get_bucket(entry_type.clone(), 0).entry())?;
		let bucket_address_1 = hdk::commit_entry(&entry_data.get_bucket(entry_type.clone(), 1).entry())?;
		let link_name_0: String = entry_data.derive_bucket_link_name(0).to_string();
		let link_name_1: String = entry_data.derive_bucket_link_name(1).to_string();
		let entry = Entry::App(
				entry_type,
				entry_data.into()
		);
		let entry_address = hdk::commit_entry(&entry)?;
		hdk::link_entries(&bucket_address_0, &entry_address, BUCKET_LINK_TYPE[0], &link_name_0)?;
		hdk::link_entries(&bucket_address_1, &entry_address, BUCKET_LINK_TYPE[1], &link_name_1)?;
		Ok(entry_address)
}

pub fn retrieve_bucket(entry_type: AppEntryType, bucket_id: String, index: usize) -> ZomeApiResult<Vec<Address>> {
		let bucket_address = BucketEntry{
				bucket_for: entry_type.to_owned(),
				id: bucket_id
		}.entry().address();
		Ok(hdk::get_links(&bucket_address, LinkMatch::Exactly(BUCKET_LINK_TYPE[index]), LinkMatch::Any)?.addresses())
}

pub fn retrieve(entry_type: AppEntryType, bucket_id: String, link_name: String, index: usize) -> ZomeApiResult<Address> {
		let bucket_address = BucketEntry{
				bucket_for: entry_type.to_owned(),
				id: bucket_id
		}.entry().address();
		let links = hdk::get_links(&bucket_address, LinkMatch::Exactly(BUCKET_LINK_TYPE[index]), LinkMatch::Exactly(&link_name))?.addresses();
    if links.len() == 1 {
        let addr = links[0].clone();
        return Ok(addr);
    } else {
        return Err(hdk::error::ZomeApiError::HashNotFound);
    }
}

pub fn retrieve_all<T: BucketIterable>(entry_type: AppEntryType, index: usize) -> ZomeApiResult<Vec<Address>> {
		Ok(
				T::buckets(index).into_iter().fold(Vec::new(), |mut addresses, bucket_id| {
						addresses.extend(retrieve_bucket(entry_type.clone(), bucket_id, index).unwrap_or(Vec::new()));
						addresses
				})
		)
}

pub fn bucket_id_from_hash_prefix<T: AddressableContent>(entry_data: T, n_prefix_bits: u32) -> String {
		let hash = entry_data.address();
		hash_prefix(hash, n_prefix_bits)
}

pub fn hash_prefix_bucket_iterator(n_prefix_bits: u32) -> Box<dyn Iterator<Item = String>> {
		let iter = (0..2^n_prefix_bits).map(|e| {
				e.to_string()
		});
		Box::new(iter)
}

fn hash_prefix(hash: Address, n_prefix_bits: u32) -> String{
		// multi-hash encoding has a prefix which tells the hashing algorithm. We need to remove this or
		// everything will be put in the same bucket
		let multihash_bytes = decode(String::from(hash)).into_vec().unwrap();
		let bytes: &[u8] = multihash::decode(&multihash_bytes).unwrap().digest;

		// encode the bucket it as a 32 bit integer stringified. Not optimal but not terrible
		let mask: u32 = 2_u32.pow(n_prefix_bits) - 1;

		// println!("{:b}", mask);
		// println!("{:b} {:b}", bytes[1], bytes[0]);

		let id = u32::from_ne_bytes([
				bytes[0],
				bytes[1],
				bytes[2],
				bytes[3],
		]) & mask;

		// println!("{:b}", id);
		id.to_string()
}



#[cfg(test)]
mod tests {
		use super::*;
		use multihash::Hash;

		#[test]
		fn test_hash_prefix() {
				// the hash of this happends to have the leading byte 00110110
				let hash = Address::encode_from_str("test daaataaaa", Hash::SHA2256);
				assert_eq!(
						hash_prefix(hash.clone(), 1),
						"0" // 0b0
				);
				assert_eq!(
						hash_prefix(hash.clone(), 2),
						"2" //0b10
				);
				assert_eq!(
						hash_prefix(hash.clone(), 3),
						"6" //0b110
				);
				assert_eq!(
						hash_prefix(hash.clone(), 4),
						"6" //0b0110
				);
		}
}
