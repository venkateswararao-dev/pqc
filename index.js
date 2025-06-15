// Import all the modules
import * as ml_kem_module from './FIPS_203/ml-kem.js';
import * as ml_dsa_module from './FIPS_204/ml-dsa.js';
import * as slh_dsa_module from './FIPS_205/slh-dsa.js';
import * as utils_module from './utilities/utils.js';
import * as crystals_module from './utilities/_crystals.js';

// Export the modules with the expected structure
export const ml_kem = ml_kem_module;
export const ml_dsa = ml_dsa_module;
export const slh_dsa = slh_dsa_module;
export const utils = utils_module;
export const _crystals = crystals_module;