// @ts-check

import { test_constant } from './deduct.js';
import os from 'os';
import minimist from 'minimist';
import fs from 'fs';
import { Input } from './deduct.js';
import crypto from 'crypto';
import { isString, isNumber } from 'util';

try{ 
    // Setting priority of current process 
    os.setPriority(os.constants.priority.PRIORITY_HIGHEST); 
}catch(err){ 
    // Printing error message if any 
    console.log(": error occured"+err); 
} 

const number_measurements = 10000;
const default_plaintext = "Sixteen byte txt";

/**
 * 
 * @param {number} num_bytes
 * @param {any} const_byte 
 */
function generate_constant_tv(num_bytes,const_byte=default_plaintext){
    return Buffer.alloc(num_bytes).fill(const_byte);
}

/**
 * 
 * @param {number} num_bytes
 */
function generate_random_tv(num_bytes, _=''){
    return crypto.randomBytes(num_bytes);
}


function generate_ec_pair(curve){
    return crypto.generateKeyPairSync('ec', {
        namedCurve: curve
      });
}

function generate_rsa_pair(key_size){
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: key_size,
      });
}

function generate_dsa_pair(key_size,q_size){
    return crypto.generateKeyPairSync('dsa', {
        modulusLength: key_size,
        divisorLength: q_size
      });
}

/**
 * 
 * @param {number} num_bytes
 * @param {function} func1 
 * @param {function} func2 
 * @param {string|Buffer|number} const_byte1
 * @param {string|Buffer|number} const_byte2
 */
function prepare_inputs(num_bytes1,num_bytes2,func1,func2,const_byte1=default_plaintext,const_byte2=default_plaintext){

    function prepare_inputs(){
        var inputs = []
        for(var i=0; i<number_measurements; i++){
            var class_id = getRandomArbitrary(0,2)
            if (class_id == 0){
                inputs.push(new Input(func1(num_bytes1,const_byte1),0));
            }
            else{
                inputs.push(new Input(func2(num_bytes2,const_byte2),1));
                //inputs.push(new Input(crypto.randomBytes(16), 1));
            }
        }
    
        return inputs;
    }

    return prepare_inputs;
}


function init_cipher(filepath,fix_key=true,fix_nonce=true,special_test=false){
    let conf = fs.readFileSync(filepath);
    var conf_json = JSON.parse(conf.toString());
    const conf_algorithm = conf_json.algorithm;
    const conf_key = conf_json.key;
    const conf_key_length = conf_json.key_length;
    const conf_nonce = Buffer.from(conf_json.nonce);
    const conf_nonce_length = conf_json.nonce_length;

    /**
     * 
     * @param {number} class_id 
     */
    function init(class_id){
        const algorithm = conf_algorithm;
        var key = conf_key;
        if (class_id == 1 && !fix_key){
            if(special_test){
                key = generate_constant_tv(conf_key_length,0);
            }
            else{
                key = generate_random_tv(conf_key_length);
            }
        }

        var iv = conf_nonce;
        if(class_id == 1 && !fix_nonce){
            if(special_test){
                iv = generate_constant_tv(conf_nonce_length,0);
            }
            else{
                iv = generate_random_tv(conf_nonce_length);
            }
        }


        const cipher = crypto.createCipheriv(algorithm, key, iv);

        /**
         * 
         * @param {Buffer} in_msg 
         */
        function do_computation(in_msg){
            cipher.update(in_msg);
        }

        return do_computation;
    }

    return init;
}

function init_rsa(filepath,fix_key=true){

    let conf = fs.readFileSync(filepath);
    var conf_json = JSON.parse(conf.toString());
    const conf_key = fs.readFileSync(conf_json.key).toString();
    const conf_key_size = conf_json.key_size;

    /**
     * 
     * @param {number} class_id 
     */
    function init(class_id){

        /**
         * @type {string|crypto.KeyObject}
         */
        var private_key = conf_key;
        if (class_id == 1 && !fix_key){
            private_key = generate_rsa_pair(conf_key_size)['privateKey'];
        }
        const sign = crypto.createSign('SHA256');
        /**
         * 
         * @param {Buffer} in_msg 
         */
        function do_computation(in_msg){
            sign.update(in_msg);
            sign.end();
            const signature = sign.sign(private_key);
        }

        return do_computation;
    }

    return init;
}

function init_dsa(filepath,fix_key=true){

    let conf = fs.readFileSync(filepath);
    var conf_json = JSON.parse(conf.toString());
    const conf_key = fs.readFileSync(conf_json.key).toString();
    const conf_key_size = conf_json.key_size;
    const conf_q_size = conf_json.q_size;

    /**
     * 
     * @param {number} class_id 
     */
    function init(class_id){

        /**
         * @type {string|crypto.KeyObject}
         */
        var private_key = conf_key;
        if (class_id == 1 && !fix_key){
            private_key = generate_dsa_pair(conf_key_size,conf_q_size)['privateKey'];
        }
        const sign = crypto.createSign('SHA256');
        /**
         * 
         * @param {Buffer} in_msg 
         */
        function do_computation(in_msg){
            sign.update(in_msg);
            sign.sign(private_key);
        }

        return do_computation;
    }

    return init;
}

function init_ec(filepath,fix_key=true){

    let conf = fs.readFileSync(filepath);
    var conf_json = JSON.parse(conf.toString());
    const conf_key = fs.readFileSync(conf_json.key).toString();
    const conf_curve = conf_json.curve;

    /**
     * 
     * @param {number} class_id 
     */
    function init(class_id){

        /**
         * @type {string|crypto.KeyObject}
         */
        var private_key = conf_key;
        if (class_id == 1 && !fix_key){
            private_key = generate_ec_pair(conf_curve)['privateKey'];
        }
        const sign = crypto.createSign('SHA256');
        /**
         * 
         * @param {Buffer} in_msg 
         */
        function do_computation(in_msg){
            sign.update(in_msg);
            sign.sign(private_key);
        }

        return do_computation;
    }

    return init;
}

function init_hash(hash_func){
    
    /**
     * 
     * @param {number} class_id 
     */
    function init(class_id){

        const hash = crypto.createHash(hash_func);
        /**
         * 
         * @param {Buffer} in_msg 
         */
        function do_computation(in_msg){
            hash.update(in_msg);
            hash.digest();
        }

        return do_computation;
    }

    return init;
}

function init_hmac(filepath,fix_key=true){

    let conf = fs.readFileSync(filepath);
    var conf_json = JSON.parse(conf.toString());
    const conf_func = conf_json.func;
    const conf_key = conf_json.key;
    const conf_key_size = conf_json.key_size;
    /**
     * 
     * @param {number} class_id 
     */
    function init(class_id){

        var key = conf_key;
        if (class_id == 1 && !fix_key){           
            key = generate_random_tv(conf_key_size);
        }
        const hmac = crypto.createHmac(conf_func, key);
        /**
         * 
         * @param {Buffer} in_msg 
         */
        function do_computation(in_msg){
            hmac.update(in_msg);
            hmac.digest();
        }

        return do_computation;
    }

    return init;
}

function init_equality(target){

    /**
     * 
     * @param {number} class_id 
     */
    function init(class_id){

        const default_str = generate_constant_tv(128);
        // var str1, str2;
        // if(class_id == 0){
        //     str1 = generate_constant_tv(16);
        //     str2 = generate_constant_tv(16);
        // }
        // else{
        //     str1 = generate_constant_tv(1024*1024);
        //     str2 = generate_constant_tv(1024*1024);
        // }
       
        /**
         * 
         * @param {Buffer} in_msg 
         */
        function do_computation(in_msg){
            
            if(target=='tsEqual'){
                crypto.timingSafeEqual(default_str,in_msg);
                //default_str.equals(in_msg);
                //str1.equals(str2);
                //isEqual(default_str,in_msg);
            }
            else{
                default_str.equals(in_msg);
            }
        }

        return do_computation;
    }

    return init;
}

// function isEqual(otherBuffer) {
  
//     if (this === otherBuffer)
  
//       return true;
  
  
  
//     if (this.byteLength !== otherBuffer.byteLength)
  
//       return false;
  
  
  
//     return this.byteLength === 0 || _compare(this, otherBuffer) === 0;
  
//   };


/**
 * Returns a random number between min (inclusive) and max (exclusive)
 */
function getRandomArbitrary(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function generateMsg(num_msgs,num_bytes=16){
    var msgs = [];
    for(var i=0; i < num_msgs; i++){
        msgs.push(generate_random_tv(num_bytes));
    }
    return msgs;
}

const msgs100 = generateMsg(100);


function cipher_tests(idx,target){
    switch(idx){
        case 1:
            console.log(`test1 for ${target}`);
            test_constant(init_cipher(target,false,true),prepare_inputs(16,16,generate_constant_tv,generate_constant_tv),true);
            break;
        case 2:
            console.log(`test2 for ${target}`);
            for(var m of msgs100){
                test_constant(init_cipher(target,false,true,true),prepare_inputs(16,16,generate_constant_tv,generate_constant_tv,m,m),true);
            }
            break;
        case 3:
            console.log(`test3 for ${target}`);
            test_constant(init_cipher(target),prepare_inputs(16,16,generate_constant_tv,generate_random_tv),false);
            break;
        case 4:
            console.log(`test4 for ${target}`);
            test_constant(init_cipher(target),prepare_inputs(16,16,generate_constant_tv,generate_constant_tv,default_plaintext,0),false);
            test_constant(init_cipher(target),prepare_inputs(16,16,generate_constant_tv,generate_constant_tv,default_plaintext,1),false);
            break;
        case 5:
            console.log(`test5 for ${target}`);
            test_constant(init_cipher(target,true,false),prepare_inputs(16,16,generate_constant_tv,generate_constant_tv),true);
            break;
        case 6:
            console.log(`test6 for ${target}`);
            for(var m of msgs100){
                test_constant(init_cipher(target,true,false,true),prepare_inputs(16,16,generate_constant_tv,generate_constant_tv,m,m),true);
            }
            break;
    }
}

function sign_tests(idx,target){

    var init_sign;
    if(target.includes('rsa')){
        init_sign = init_rsa;
    }
    else if(target.includes('dsa')){
        init_sign = init_dsa;
    }
    else if(target.includes('ec')){
        init_sign = init_ec;
    }

    switch(idx){
        case 1:
            console.log(`test1 for ${target}`);
            test_constant(init_sign(target),prepare_inputs(16,16,generate_constant_tv,generate_random_tv),true);
            break;
        case 2:
            console.log(`test2 for ${target}`);
            test_constant(init_sign(target,false),prepare_inputs(16,16,generate_constant_tv,generate_constant_tv),true);
            break;
    }
}

function hash_tests(idx,target){

    switch(idx){
        case 1:
            console.log(`test1 for ${target}`);
            test_constant(init_hash(target),prepare_inputs(16,16,generate_constant_tv,generate_random_tv),true);
            //test_constant(init_hash(target),prepare_inputs(16,1024*1024,generate_constant_tv,generate_constant_tv),true);
            break;
    
    }
}

function hmac_tests(idx,target){

    switch(idx){
        case 1:
            console.log(`test1 for ${target}`);
            test_constant(init_hmac(target,false),prepare_inputs(16,16,generate_constant_tv,generate_constant_tv),true);
            break;
    
    }
}

function equality_tests(idx,target){

    switch(idx){
        case 1:
            console.log(`test1 for ${target}`);
            test_constant(init_equality(target),prepare_inputs(128,128,generate_constant_tv,generate_random_tv),false);
            break;
    
    }
}

const args = minimist(process.argv.slice(2));
var do_test;
if(args.n == 'cipher'){
    do_test = cipher_tests;
}
else if(args.n == 'sign'){
    do_test = sign_tests;
}
else if(args.n == 'hash'){
    do_test = hash_tests;
}
else if(args.n == 'hmac'){
    do_test = hmac_tests;
}
else if(args.n == 'equality'){
    do_test = equality_tests;
}

const target = args.t;
if(isNumber(args.i)){
    do_test(args.i,args.t);
}
else{
    const idxs = args.i.split('-');
    for(var i = parseInt(idxs[0]); i <= parseInt(idxs[1]); i++){
        do_test(i,target);
    }
}

