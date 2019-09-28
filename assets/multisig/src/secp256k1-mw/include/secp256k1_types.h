/*
 * secp256k1_types.h
 *
 *  Created on: Apr 21, 2019
 *      Author: akiracam
 */

#ifndef SRC_SECP256K1_MW_INCLUDE_SECP256K1_TYPES_H_
#define SRC_SECP256K1_MW_INCLUDE_SECP256K1_TYPES_H_

#include "../src/ecmult.h"
#include "../src/ecmult_gen.h"
#include "../src/util.h"

struct secp256k1_context_struct2 {
    secp256k1_ecmult_context ecmult_ctx;
    secp256k1_ecmult_gen_context ecmult_gen_ctx;
    secp256k1_callback illegal_callback;
    secp256k1_callback error_callback;
};

#endif /* SRC_SECP256K1_MW_INCLUDE_SECP256K1_TYPES_H_ */
