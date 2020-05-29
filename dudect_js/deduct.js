//@ts-check

import { strict as assert } from 'assert';
import {performance} from 'perf_hooks';

const number_percentiles = 10000; //Number of t-tests we will do on the test results
const enough_measurements = 10000; // Threshold for enough large measurements
const number_tests = 1 + number_percentiles + 1;

const t_threshold_bananas = 500;
const t_threshold_moderate = 10;

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

    compute(){
        var v = [0.0, 0.0];
        v[0] = this.m2[0] / (this.n[0] - 1);
        v[1] = this.m2[1] / (this.n[1] - 1);
        var num = this.mean[0] - this.mean[1];
        var den = (v[0] / this.n[0] + v[1] / this.n[1]) ** 0.5;
        var t_value = num / den;
        return t_value;
    }
}

/**
 * 
 * @typedef {Buffer} bytes
 * @param {function} init 
 * @param {function(any): Array.<Object.<string,(bytes|number)>>} prepare_inputs 
 * @param {function(any,bytes): any} do_one_computation 
 */
export function test_constant(init, prepare_inputs,do_one_computation){
    /**
     *  Test whether a computation is constant-time statistically against two provided classes of inputs.
        TODO: Make it the only public function to external in this package.
        Args:
            init: A function, which initializes the state for measurement.
            prepare_inputs: A function, which must take the return of `init` function as argument (you may ignore it in the
                function body) and return a List of Dict{"data": bytes, "class_id": int}.
                TODO: Make the inputs data representation better?
            do_one_computation: A function, which takes as the first argument the return of `init` function and as the
                second argument one input data (bytes) to be computed (from the return of `prepare_inputs` function), and
                then do the to be measured computation based on them.

        Returns:
            No return. Print the test conclusion to stdout.
     */
    var init_result = init();
    var inputs = prepare_inputs(init_result);
    var number_measuremnts = inputs.length;

    /**
     * @type {Array.<number>}
     */
    var measurements = do_measurement(init_result, inputs, number_measuremnts, do_one_computation);
    var percentiles = prepare_percentiles(measurements);
    var t = update_statics(measurements, inputs, percentiles);
    report(t);
}

/**
 * 
 * @param {any} init 
 * @param {Array.<Object>} inputs 
 * @param {number} number_measuremnts 
 * @param {function} do_one_computation
 * @return {Array.<number>} 
 */
function do_measurement(init, inputs, number_measuremnts, do_one_computation){

    var measurements = []
    for(var i=0; i < number_measuremnts; i++){
        var start = performance.now();
        do_one_computation(init, inputs[i]['data']);
        var end = performance.now();
        measurements.push(end-start);
    }
    
    return measurements;
}


/**
 * 
 * @param {Array.<number>} data
 * @return {Array.<number>} 
 */
function prepare_percentiles(data){
    var sorted = data.sort(function(a,b){return a-b});
    var ps = []
    for(var i=0; i<number_percentiles; i++){
        ps.push(percentile(sorted, 1 - 0.5 ** (10 * (i+1) / number_percentiles)));
    }

    return ps;

}

/**
 * 
 * @param {Array.<number>} measurements 
 * @param {Array.<Object>} inputs 
 * @param {Array.<number>} percentiles
 * @return {Array.<TestData>} 
 */
function update_statics(measurements, inputs, percentiles){

    var t = []
    for(var i=0; i < number_tests; i++){
        t.push(new TestData([0.0,0.0],[0.0, 0.0],[0,0]))
    }
    
    for(var i=0; i < measurements.length; i++){
        var data = measurements[i];
        var class_id = inputs[i]['class']

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
        max_tau = max_t / max_t_n ** 0.5;
    
    console.log(`total measurements: ${(max_t_n / 1e6).toFixed(2)} Million`);
    console.log(`max t-value: ${max_t.toFixed(2)}, max tau: ${max_tau.toExponential(2)}, (5.tau)^2: ${((5 * 5) / (max_tau * max_tau)).toExponential(2)}`);

    if (max_t > t_threshold_bananas){
        console.log("Definitely not constant time.");
        return;
    }
    if (max_t > t_threshold_moderate){
        console.log("Probably not constant time.");
        return;
    }
    if (max_t <= t_threshold_moderate){
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
    var test_id = 0, maximum = 0;

    for(var i=0; i < number_tests; i++){
        if (t[i].n[0] + t[i].n[1] > enough_measurements){
            var temp = Math.abs(t[i].compute());
            if (temp > maximum){
                maximum = temp;
                test_id = i;
            }
        }
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