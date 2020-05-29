// @ts-check

import { test_constant } from './deduct.js';
import crypto from "crypto"
//const crypto = require('crypto');

const number_measurements = 100000

function prepare_inputs(){
    var inputs = []
    for(var i=0; i<number_measurements; i++){
        var class_id = getRandomArbitrary(0,2)
        if (class_id == 0){
            inputs.push({"data": Buffer.alloc(16),"class": 0});
        }
        else{
            inputs.push({"data": crypto.randomBytes(16), "class": 1});
        }
    }

    return inputs;
}

function init(){
    const algorithm = 'aes-128-cbc';
    const password = 'Sixteen byte key';
    const key = crypto.scryptSync(password, 'salt', 16);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);

    return cipher;
}

/**
 * 
 * @param {crypto.Cipher} cipher 
 * @param {Buffer} in_msg 
 */
function do_computation(cipher, in_msg){
    cipher.update(in_msg);
}
/**
 * Returns a random number between min (inclusive) and max (exclusive)
 */
function getRandomArbitrary(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

test_constant(init,prepare_inputs,do_computation);