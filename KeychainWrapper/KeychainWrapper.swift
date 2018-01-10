//
//  KeychainService.swift
//  TTS_Words_And_Weather
//
//  Created by Franks, Kent Eric on 3/27/17.
//  Copyright © 2017 KefBytes. All rights reserved.
//

import Foundation
import Security

// Constant Identifiers
let userAccount = "AuthenticatedUser"
let accessGroup = "SecuritySerivice"


/**
 *  User defined keys for new entry
 *  Note: add new keys for new secure item and use them in load and save methods
 */

let passwordKey = "TTSPasswordsApp_Password"

// Arguments for the keychain queries
let kSecClassValue = String(format: kSecClass as String)
let kSecAttrAccountValue = String(format: kSecAttrAccount as String)
let kSecValueDataValue = String(format: kSecValueData as String)
let kSecClassGenericPasswordValue = String(format: kSecClassGenericPassword as String)
let kSecAttrServiceValue = String(format: kSecAttrService as String)
let kSecMatchLimitValue = String(format: kSecMatchLimit as String)
let kSecReturnDataValue = String(format: kSecReturnData as String)
let kSecMatchLimitOneValue = String(format: kSecMatchLimitOne as String)

public class KeychainService: NSObject {
    
    /**
     * Exposed methods to perform save and load queries.
     */
    
    public class func savePassword(token: String) {
        self.save(service: passwordKey as String, data: token)
    }
    
    public class func loadPassword() -> String? {
        return self.load(service: passwordKey as String)
    }
    
    /**
     * Internal methods for querying the keychain.
     */
    
    private class func save(service: String, data: String) {
        let dataFromString: NSData = data.data(using: String.Encoding(rawValue: String.Encoding.utf8.rawValue), allowLossyConversion: false)! as NSData
        
        // Instantiate a new default keychain query
        let keychainQuery: NSMutableDictionary = NSMutableDictionary(objects: [kSecClassGenericPasswordValue, service, userAccount, dataFromString], forKeys: [kSecClassValue as NSCopying, kSecAttrServiceValue as NSCopying, kSecAttrAccountValue as NSCopying, kSecValueDataValue as NSCopying])
        
        // Delete any existing items
        SecItemDelete(keychainQuery as CFDictionary)
        
        // Add the new keychain item
        SecItemAdd(keychainQuery as CFDictionary, nil)
    }
    
    private class func load(service: String) -> String? {
        // Instantiate a new default keychain query
        // Tell the query to return a result
        // Limit our results to one item
        let keychainQuery: NSMutableDictionary = NSMutableDictionary(objects: [kSecClassGenericPasswordValue, service, userAccount, kCFBooleanTrue, kSecMatchLimitOneValue], forKeys: [kSecClassValue as NSCopying, kSecAttrServiceValue as NSCopying, kSecAttrAccountValue as NSCopying, kSecReturnDataValue as NSCopying, kSecMatchLimitValue as NSCopying])
        
        var dataTypeRef :AnyObject?
        
        // Search for the keychain items
        let status: OSStatus = SecItemCopyMatching(keychainQuery, &dataTypeRef)
        var contentsOfKeychain: String? = nil
        
        if status == errSecSuccess {
            if let retrievedData = dataTypeRef as? NSData {
                contentsOfKeychain = String(data: retrievedData as Data, encoding: String.Encoding(rawValue: String.Encoding.utf8.rawValue))
            }
        } else {
            print("Nothing was retrieved from the keychain. Status code \(status)")
        }
        
        return contentsOfKeychain
    }
}



