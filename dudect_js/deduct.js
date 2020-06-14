//@ts-check

import { strict as assert } from 'assert';
import {performance} from 'perf_hooks';

const number_percentiles = 100; //Number of percentiles we will do on the test results
const enough_measurements = 1000; // Threshold for enough large measurements
const number_tests = 1 + number_percentiles + 1; //Number of t-tests we will do on the test results

const t_threshold_bananas = 500;
const t_threshold_moderate = 10;
const zAlphaHalf         = 1.96  // alpha = 0.05
const zBeta              = 1.645 // beta = 0.05

class TestData {

    /**
     * @type {Array.<number>}
     */
    mean = [0.0, 0.0];
    /**
     * @type {Array.<number>}
     */
    m2 = [0.0, 0.0];
    /**
     * @type {Array.<number>}
     */
    n = [0, 0];

    /**
     * 
     * @param {Array.<number>} mean 
     * @param {Array.<number>} m2 
     * @param {Array.<number>} n 
     */
    constructor(mean, m2, n){
        this.mean = mean;
        this.m2 = m2;
        this.n = n;
    }

    /**
     * 
     * @param {number} new_data 
     * @param {number} classes 
     */
    push(new_data,classes){
        assert(classes==0 || classes==1, "classes should be 0 or 1");
        this.n[classes] += 1;
        var delta = new_data - this.mean[classes];
        this.mean[classes] = this.mean[classes] + delta / this.n[classes];
        this.m2[classes] = this.m2[classes] + delta * (new_data - this.mean[classes]);
    }

    /**
     * @return {number}
     */
    compute(){
        var v = [0.0, 0.0];
        v[0] = this.m2[0] / (this.n[0] - 1);
        v[1] = this.m2[1] / (this.n[1] - 1);
        var num = this.mean[0] - this.mean[1];
        var den = (v[0] / this.n[0] + v[1] / this.n[1]) ** 0.5;
        var t_value = num / den;
        return t_value;
    }

    /**
     * 
     * @param {boolean} verbose
     */
    enoughSample(verbose){
        
        if(this.n[0] <= 1 || this.n[1] <= 1){
            return {'enough':false,'dis':0.0};
        }
        var variance = [0.0,0.0];
        variance[0] = (this.m2[0] / (this.n[0] - 1)) ** 0.5;
        variance[1] = (this.m2[1] / (this.n[1] - 1)) ** 0.5;

        var r = this.n[0] / this.n[1];
        if(r < 1){
            r = 1/r;
        }
        if(verbose){
            console.log(`variance: ${variance}`);
            console.log(`ratio: ${r}`);
            console.log(`mean delta: ${this.mean[0]-this.mean[1]}`);
        }

        var n = (variance[0]**2 + (variance[1]**2)/r) * ((zAlphaHalf+zBeta)**2) / ((this.mean[0]-this.mean[1])**2);
        var smallerSample = Math.min(this.n[0], this.n[1]);
        if(smallerSample < n){
            if(verbose){
                console.log(`${n.toFixed(0)} is suggested, while the smaller class has only ${smallerSample.toFixed(2)} population (${(smallerSample/n*100).toFixed(2)})`);
            }
            return {'enough': false, 'dis': smallerSample/n};
        }
        return {'enough': true, 'dis': 1};

    }
}

export class Input {
    /**
     *
        The class representation of a single input.

        Args:
            data: the bytes data to be fed into computation.
            cla: the categorization of this data as 0 or 1.

        Attributes:
            Data: the bytes data to be fed into computation.
            Class: the categorization of this data as 0 or 1.
     */


    /**
     * 
     * @param {bytes} data 
     * @param {number} cla 
     */
    constructor(data, cla){

        /**
         * @type {bytes}
         */
        this.Data = data;

        /**
         * @type {number}
         */
        this.Class = cla;
    }
    
}

/**
 * 
 * @typedef {Buffer} bytes
 * @param {function(number): (function(bytes): void)} init 
 * @param {function(): Array.<Input>} prepare_inputs 
 * @param {boolean} init_repeatedly
 */
export function test_constant(init, prepare_inputs, init_repeatedly){
    /**
     * 
        Test whether a computation is constant-time statistically against two provided classes of inputs.
        TODO: Make it the only public function to external in this package.
        Args:
            init: A function, which initializes the state for computations, returns a closure func to do one computation.
            prepare_inputs: A function returns a List of Input.
            init_repeatedly: decide whether the init function should be executed once for every single measurement or once
                for all measurements.

        Returns:
            No return. Print the test conclusion to stdout.
     */
    var inputs = prepare_inputs();

    /**
     * @type {Array.<number>}
     */
    var measurements = do_measurement(init, inputs, init_repeatedly);

    var t = update_statics(measurements, inputs);
    report(t);
}

/**
 * 
 * @param {function(number): (function(bytes): void)} init 
 * @param {Array.<Input>} inputs 
 * @param {boolean} [init_repeatedly=false] 
 * @return {Array.<number>} 
 */
function do_measurement(init, inputs, init_repeatedly){

    var number_measuremnts = inputs.length;

    /**
     * @type {Array.<number>}
     */
    var measurements = [];

    if (!init_repeatedly){
        var do_one_computation = init(0);
        for(var i=0; i < number_measuremnts; i++){
            var start = performance.now();
            do_one_computation(inputs[i].Data);
            var end = performance.now();
            measurements.push(end-start);
        }
    }
    else {
        for(var i=0; i < number_measuremnts; i++){
            
            var do_one_computation = init(inputs[i].Class);
            var start = performance.now();
            do_one_computation(inputs[i].Data);
            var end = performance.now();
            measurements.push(end-start);
        }
    }
    
    return measurements;
}


/**
 * 
 * @param {Array.<number>} data
 * @return {Array.<number>} 
 */
function prepare_percentiles(data){
    var sorted = [...data].sort(function(a,b){return a-b});
    var ps = []
    for(var i=0; i<number_percentiles; i++){
        ps.push(percentile(sorted, 1 - 0.5 ** (10 * (i+1) / number_percentiles)));
    }

    return ps;

}

/**
 * 
 * @param {Array.<number>} measurements 
 * @param {Array.<Input>} inputs 
 * @return {Array.<TestData>} 
 */
function update_statics(measurements, inputs){

    var percentiles = prepare_percentiles(measurements);

    /**
     * @type {Array.<TestData>}
     */
    var t = []
    for(var i=0; i < number_tests; i++){
        t.push(new TestData([0.0,0.0],[0.0, 0.0],[0,0]))
    }
    
    for(var i=0; i < measurements.length; i++){
        var data = measurements[i];
        var class_id = inputs[i].Class

        assert(data > 0, "data should be larger than 0.");
        t[0].push(data, class_id);

        for(var j=0; j < percentiles.length; j++){
            if(data < percentiles[j]){
                t[j+1].push(data, class_id);
            }
        }

        if (t[0].n[0] > 10000){
            var centerd = data - t[0].mean[class_id];
            t[number_tests-1].push(centerd ** 2, class_id);
        }

    }

    return t;
}

/**
 * 
 * @param {Array.<TestData>} t 
 */
function report(t){
    var mt = max_test(t),
        max_t = Math.abs(t[mt].compute()),
        max_t_n = t[mt].n[0] + t[mt].n[1],
        max_tau = max_t / (max_t_n ** 0.5),
        overall_t = Math.abs(t[0].compute()),
        overall_t_n = t[0].n[0] + t[0].n[1],
        overall_tau = overall_t / (overall_t_n ** 0.5);

    console.log(`total measurements: ${(max_t_n / 1e6).toFixed(2)} Million`);
    console.log(`class-0 mean overall: ${(t[0].mean[0]).toExponential(2)}, population: ${t[0].n[0]}; class-1 mean overall: ${(t[0].mean[1]).toExponential(2)}, population: ${t[0].n[1]}`);

    console.log(`class-0 mean of max_t: ${(t[mt].mean[0]).toExponential(2)}, population: ${t[mt].n[0]}; class-1 mean of max_t: ${(t[mt].mean[1]).toExponential(2)}, population: ${t[mt].n[1]}`);
    
    console.log(`overall t-value: ${overall_t.toFixed(2)}, max tau: ${overall_tau.toExponential(2)}, (5.tau)^2: ${((5 * 5) / (overall_tau * overall_tau)).toExponential(2)}`);

    console.log(`max t-value: ${max_t.toFixed(2)}, max tau: ${max_tau.toExponential(2)}, (5.tau)^2: ${((5 * 5) / (max_tau * max_tau)).toExponential(2)}`);

    if (max_t > t_threshold_bananas){
        console.log("Definitely not constant time.");
        return;
    }
    if (max_t > t_threshold_moderate){
        console.log("Probably not constant time.");
        return;
    }
    //if (max_t <= t_threshold_moderate){
    else{
        console.log("For the moment, maybe constant time.");
    }
    return;
}

/**
 * 
 * @param {Array.<TestData>} t
 * @return {number} 
 */
function max_test(t){
    var test_id = 0, maximum = 0, max_dis = 0;

    for(var i=0; i < number_tests; i++){
        var {enough,dis} = t[i].enoughSample(false);
        
        if(enough){
            var temp = Math.abs(t[i].compute());
            if (temp > maximum){
                maximum = temp;
                test_id = i;
            }
        }
        else{
            if (dis > max_dis){
                max_dis = dis;
                test_id = i;
            }
        }
    }

    if (maximum == 0){
        console.log(`Sample size is not large enough, using ${test_id}-th smaple closest to the suggested size for t-value computation.`);
        t[test_id].enoughSample(true);
    }
    else{
        console.log(`Sample under percentile ${((1 - 0.5**(10*test_id/number_percentiles))*100).toFixed(2)} is computed to have the max-t`);
    }

    return test_id;
}

/**
 * 
 * @param {Array.<number>} arr 
 * @param {number} p 
 */
function percentile(arr, p) {

    if (arr.length === 0) return 0;

    if (p <= 0) return arr[0];
    if (p >= 1) return arr[arr.length - 1];

    var index = (arr.length - 1) * p,

        lower = Math.floor(index),

        upper = lower + 1,

        weight = index % 1;

    if (upper >= arr.length) return arr[lower];

    return arr[lower] * (1 - weight) + arr[upper] * weight;

}