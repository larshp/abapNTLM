class ZCL_NTLM_DES definition
  public
  create public .

public section.

  types:
    ty_byte7 TYPE x LENGTH 7 .
  types:
    ty_byte8 TYPE x LENGTH 8 .

  class-methods CLASS_CONSTRUCTOR .
  class-methods ENCRYPT
    importing
      !IV_KEY type TY_BYTE8
      !IV_PLAINTEXT type XSEQUENCE
    returning
      value(RV_CIPHERTEXT) type XSTRING .
  class-methods PARITY_ADJUST
    importing
      !IV_BYTE7 type TY_BYTE7
    returning
      value(RV_BYTE8) type TY_BYTE8 .
  PROTECTED SECTION.

    TYPES:
*"* protected components of class ZCL_NTLM_DES
*"* do not include other source files here!!!
      tty_itab TYPE STANDARD TABLE OF i WITH DEFAULT KEY .
  PRIVATE SECTION.

    CLASS-DATA mt_e TYPE tty_itab .
    CLASS-DATA mt_ip TYPE tty_itab .
    CLASS-DATA mt_ip1 TYPE tty_itab .
    CLASS-DATA mt_p TYPE tty_itab .
    CLASS-DATA mt_pc1 TYPE tty_itab .
    CLASS-DATA mt_pc2 TYPE tty_itab .
    CLASS-DATA mt_s1 TYPE tty_itab .
    CLASS-DATA mt_s2 TYPE tty_itab .
    CLASS-DATA mt_s3 TYPE tty_itab .
    CLASS-DATA mt_s4 TYPE tty_itab .
    CLASS-DATA mt_s5 TYPE tty_itab .
    CLASS-DATA mt_s6 TYPE tty_itab .
    CLASS-DATA mt_s7 TYPE tty_itab .
    CLASS-DATA mt_s8 TYPE tty_itab .

    CLASS-METHODS permute
      IMPORTING
        !iv_bits        TYPE clike
        !it_permutation TYPE tty_itab
      RETURNING
        VALUE(rv_bits)  TYPE string .
    CLASS-METHODS xor
      IMPORTING
        !iv_a         TYPE clike
        !iv_b         TYPE clike
      RETURNING
        VALUE(rv_res) TYPE string .
    CLASS-METHODS to_bits
      IMPORTING
        !iv_binary     TYPE xsequence
      RETURNING
        VALUE(rv_bits) TYPE string .
    CLASS-METHODS s8
      IMPORTING
        !iv_b       TYPE clike
      RETURNING
        VALUE(rv_s) TYPE string .
    CLASS-METHODS s7
      IMPORTING
        !iv_b       TYPE clike
      RETURNING
        VALUE(rv_s) TYPE string .
    CLASS-METHODS s6
      IMPORTING
        !iv_b       TYPE clike
      RETURNING
        VALUE(rv_s) TYPE string .
    CLASS-METHODS s5
      IMPORTING
        !iv_b       TYPE clike
      RETURNING
        VALUE(rv_s) TYPE string .
    CLASS-METHODS s4
      IMPORTING
        !iv_b       TYPE clike
      RETURNING
        VALUE(rv_s) TYPE string .
    CLASS-METHODS s3
      IMPORTING
        !iv_b       TYPE clike
      RETURNING
        VALUE(rv_s) TYPE string .
    CLASS-METHODS s2
      IMPORTING
        !iv_b       TYPE clike
      RETURNING
        VALUE(rv_s) TYPE string .
    CLASS-METHODS s1
      IMPORTING
        !iv_b       TYPE clike
      RETURNING
        VALUE(rv_s) TYPE string .
    CLASS-METHODS row
      IMPORTING
        !iv_b         TYPE clike
      RETURNING
        VALUE(rv_row) TYPE i .
    CLASS-METHODS permute_pc2
      IMPORTING
        !iv_bits       TYPE clike
      RETURNING
        VALUE(rv_bits) TYPE string .
    CLASS-METHODS permute_pc1
      IMPORTING
        !iv_bits       TYPE clike
      RETURNING
        VALUE(rv_bits) TYPE string .
    CLASS-METHODS permute_p
      IMPORTING
        !iv_bits       TYPE clike
      RETURNING
        VALUE(rv_bits) TYPE string .
    CLASS-METHODS permute_ip1
      IMPORTING
        !iv_bits       TYPE clike
      RETURNING
        VALUE(rv_bits) TYPE string .
    CLASS-METHODS permute_ip
      IMPORTING
        !iv_bits       TYPE clike
      RETURNING
        VALUE(rv_bits) TYPE string .
    CLASS-METHODS permute_e
      IMPORTING
        !iv_bits       TYPE clike
      RETURNING
        VALUE(rv_bits) TYPE string .
    CLASS-METHODS l_and_r
      IMPORTING
        !iv_l_0        TYPE clike
        !iv_r_0        TYPE clike
        !it_k          TYPE string_table
      RETURNING
        VALUE(rv_bits) TYPE string .
    CLASS-METHODS k
      IMPORTING
        !it_bits       TYPE string_table
      RETURNING
        VALUE(rt_bits) TYPE string_table .
    CLASS-METHODS i_to_bits_4
      IMPORTING
        !iv_i          TYPE i
      RETURNING
        VALUE(rv_bits) TYPE string .
    CLASS-METHODS from_bits
      IMPORTING
        !iv_bits       TYPE clike
      RETURNING
        VALUE(rv_xstr) TYPE xstring .
    CLASS-METHODS f
      IMPORTING
        !iv_r         TYPE clike
        !iv_k         TYPE clike
      RETURNING
        VALUE(rv_res) TYPE string .
    CLASS-METHODS c_and_d
      IMPORTING
        !iv_c_0        TYPE clike
        !iv_d_0        TYPE clike
      RETURNING
        VALUE(rt_bits) TYPE string_table .
    CLASS-METHODS column
      IMPORTING
        !iv_b            TYPE clike
      RETURNING
        VALUE(rv_column) TYPE i .
*"* private components of class ZCL_NTLM_DES
*"* do not include other source files here!!!
ENDCLASS.



CLASS ZCL_NTLM_DES IMPLEMENTATION.


  METHOD CLASS_CONSTRUCTOR.
    mt_e = VALUE #(
      ( 32 ) ( 1 ) ( 2 ) ( 3 ) ( 4 ) ( 5 ) ( 4 ) ( 5 )
      ( 6 ) ( 7 ) ( 8 ) ( 9 ) ( 8 ) ( 9 ) ( 10 ) ( 11 )
      ( 12 ) ( 13 ) ( 12 ) ( 13 ) ( 14 ) ( 15 ) ( 16 ) ( 17 )
      ( 16 ) ( 17 ) ( 18 ) ( 19 ) ( 20 ) ( 21 ) ( 20 ) ( 21 )
      ( 22 ) ( 23 ) ( 24 ) ( 25 ) ( 24 ) ( 25 ) ( 26 ) ( 27 )
      ( 28 ) ( 29 ) ( 28 ) ( 29 ) ( 30 ) ( 31 ) ( 32 ) ( 1 ) ).

    mt_ip = VALUE #(
      ( 58 ) ( 50 ) ( 42 ) ( 34 ) ( 26 ) ( 18 ) ( 10 ) ( 2 )
      ( 60 ) ( 52 ) ( 44 ) ( 36 ) ( 28 ) ( 20 ) ( 12 ) ( 4 )
      ( 62 ) ( 54 ) ( 46 ) ( 38 ) ( 30 ) ( 22 ) ( 14 ) ( 6 )
      ( 64 ) ( 56 ) ( 48 ) ( 40 ) ( 32 ) ( 24 ) ( 16 ) ( 8 )
      ( 57 ) ( 49 ) ( 41 ) ( 33 ) ( 25 ) ( 17 ) ( 9 ) ( 1 )
      ( 59 ) ( 51 ) ( 43 ) ( 35 ) ( 27 ) ( 19 ) ( 11 ) ( 3 )
      ( 61 ) ( 53 ) ( 45 ) ( 37 ) ( 29 ) ( 21 ) ( 13 ) ( 5 )
      ( 63 ) ( 55 ) ( 47 ) ( 39 ) ( 31 ) ( 23 ) ( 15 ) ( 7 ) ).

    mt_ip1 = VALUE #(
      ( 40 ) ( 8 ) ( 48 ) ( 16 ) ( 56 ) ( 24 ) ( 64 ) ( 32 )
      ( 39 ) ( 7 ) ( 47 ) ( 15 ) ( 55 ) ( 23 ) ( 63 ) ( 31 )
      ( 38 ) ( 6 ) ( 46 ) ( 14 ) ( 54 ) ( 22 ) ( 62 ) ( 30 )
      ( 37 ) ( 5 ) ( 45 ) ( 13 ) ( 53 ) ( 21 ) ( 61 ) ( 29 )
      ( 36 ) ( 4 ) ( 44 ) ( 12 ) ( 52 ) ( 20 ) ( 60 ) ( 28 )
      ( 35 ) ( 3 ) ( 43 ) ( 11 ) ( 51 ) ( 19 ) ( 59 ) ( 27 )
      ( 34 ) ( 2 ) ( 42 ) ( 10 ) ( 50 ) ( 18 ) ( 58 ) ( 26 )
      ( 33 ) ( 1 ) ( 41 ) ( 9 ) ( 49 ) ( 17 ) ( 57 ) ( 25 ) ).

    mt_p = VALUE #(
      ( 16 ) ( 7 ) ( 20 ) ( 21 ) ( 29 ) ( 12 ) ( 28 ) ( 17 )
      ( 1 ) ( 15 ) ( 23 ) ( 26 ) ( 5 ) ( 18 ) ( 31 ) ( 10 )
      ( 2 ) ( 8 ) ( 24 ) ( 14 ) ( 32 ) ( 27 ) ( 3 ) ( 9 )
      ( 19 ) ( 13 ) ( 30 ) ( 6 ) ( 22 ) ( 11 ) ( 4 ) ( 25 ) ).

    mt_pc1 = VALUE #(
      ( 57 ) ( 49 ) ( 41 ) ( 33 ) ( 25 ) ( 17 ) ( 9 ) ( 1 )
      ( 58 ) ( 50 ) ( 42 ) ( 34 ) ( 26 ) ( 18 ) ( 10 ) ( 2 )
      ( 59 ) ( 51 ) ( 43 ) ( 35 ) ( 27 ) ( 19 ) ( 11 ) ( 3 )
      ( 60 ) ( 52 ) ( 44 ) ( 36 ) ( 63 ) ( 55 ) ( 47 ) ( 39 )
      ( 31 ) ( 23 ) ( 15 ) ( 7 ) ( 62 ) ( 54 ) ( 46 ) ( 38 )
      ( 30 ) ( 22 ) ( 14 ) ( 6 ) ( 61 ) ( 53 ) ( 45 ) ( 37 )
      ( 29 ) ( 21 ) ( 13 ) ( 5 ) ( 28 ) ( 20 ) ( 12 ) ( 4 ) ).

    mt_pc2 = VALUE #(
      ( 14 ) ( 17 ) ( 11 ) ( 24 ) ( 1 ) ( 5 ) ( 3 ) ( 28 )
      ( 15 ) ( 6 ) ( 21 ) ( 10 ) ( 23 ) ( 19 ) ( 12 ) ( 4 )
      ( 26 ) ( 8 ) ( 16 ) ( 7 ) ( 27 ) ( 20 ) ( 13 ) ( 2 )
      ( 41 ) ( 52 ) ( 31 ) ( 37 ) ( 47 ) ( 55 ) ( 30 ) ( 40 )
      ( 51 ) ( 45 ) ( 33 ) ( 48 ) ( 44 ) ( 49 ) ( 39 ) ( 56 )
      ( 34 ) ( 53 ) ( 46 ) ( 42 ) ( 50 ) ( 36 ) ( 29 ) ( 32 ) ).

    mt_s1 = VALUE #(
      ( 14 ) ( 4 ) ( 13 ) ( 1 ) ( 2 ) ( 15 ) ( 11 ) ( 8 )
      ( 3 ) ( 10 ) ( 6 ) ( 12 ) ( 5 ) ( 9 ) ( 0 ) ( 7 )
      ( 0 ) ( 15 ) ( 7 ) ( 4 ) ( 14 ) ( 2 ) ( 13 ) ( 1 )
      ( 10 ) ( 6 ) ( 12 ) ( 11 ) ( 9 ) ( 5 ) ( 3 ) ( 8 )
      ( 4 ) ( 1 ) ( 14 ) ( 8 ) ( 13 ) ( 6 ) ( 2 ) ( 11 )
      ( 15 ) ( 12 ) ( 9 ) ( 7 ) ( 3 ) ( 10 ) ( 5 ) ( 0 )
      ( 15 ) ( 12 ) ( 8 ) ( 2 ) ( 4 ) ( 9 ) ( 1 ) ( 7 )
      ( 5 ) ( 11 ) ( 3 ) ( 14 ) ( 10 ) ( 0 ) ( 6 ) ( 13 ) ).

    mt_s2 = VALUE #(
      ( 15 ) ( 1 ) ( 8 ) ( 14 ) ( 6 ) ( 11 ) ( 3 ) ( 4 )
      ( 9 ) ( 7 ) ( 2 ) ( 13 ) ( 12 ) ( 0 ) ( 5 ) ( 10 )
      ( 3 ) ( 13 ) ( 4 ) ( 7 ) ( 15 ) ( 2 ) ( 8 ) ( 14 )
      ( 12 ) ( 0 ) ( 1 ) ( 10 ) ( 6 ) ( 9 ) ( 11 ) ( 5 )
      ( 0 ) ( 14 ) ( 7 ) ( 11 ) ( 10 ) ( 4 ) ( 13 ) ( 1 )
      ( 5 ) ( 8 ) ( 12 ) ( 6 ) ( 9 ) ( 3 ) ( 2 ) ( 15 )
      ( 13 ) ( 8 ) ( 10 ) ( 1 ) ( 3 ) ( 15 ) ( 4 ) ( 2 )
      ( 11 ) ( 6 ) ( 7 ) ( 12 ) ( 0 ) ( 5 ) ( 14 ) ( 9 ) ).

    mt_s3 = VALUE #(
      ( 10 ) ( 0 ) ( 9 ) ( 14 ) ( 6 ) ( 3 ) ( 15 ) ( 5 )
      ( 1 ) ( 13 ) ( 12 ) ( 7 ) ( 11 ) ( 4 ) ( 2 ) ( 8 )
      ( 13 ) ( 7 ) ( 0 ) ( 9 ) ( 3 ) ( 4 ) ( 6 ) ( 10 )
      ( 2 ) ( 8 ) ( 5 ) ( 14 ) ( 12 ) ( 11 ) ( 15 ) ( 1 )
      ( 13 ) ( 6 ) ( 4 ) ( 9 ) ( 8 ) ( 15 ) ( 3 ) ( 0 )
      ( 11 ) ( 1 ) ( 2 ) ( 12 ) ( 5 ) ( 10 ) ( 14 ) ( 7 )
      ( 1 ) ( 10 ) ( 13 ) ( 0 ) ( 6 ) ( 9 ) ( 8 ) ( 7 )
      ( 4 ) ( 15 ) ( 14 ) ( 3 ) ( 11 ) ( 5 ) ( 2 ) ( 12 ) ).

    mt_s4 = VALUE #(
      ( 7 ) ( 13 ) ( 14 ) ( 3 ) ( 0 ) ( 6 ) ( 9 ) ( 10 )
      ( 1 ) ( 2 ) ( 8 ) ( 5 ) ( 11 ) ( 12 ) ( 4 ) ( 15 )
      ( 13 ) ( 8 ) ( 11 ) ( 5 ) ( 6 ) ( 15 ) ( 0 ) ( 3 )
      ( 4 ) ( 7 ) ( 2 ) ( 12 ) ( 1 ) ( 10 ) ( 14 ) ( 9 )
      ( 10 ) ( 6 ) ( 9 ) ( 0 ) ( 12 ) ( 11 ) ( 7 ) ( 13 )
      ( 15 ) ( 1 ) ( 3 ) ( 14 ) ( 5 ) ( 2 ) ( 8 ) ( 4 )
      ( 3 ) ( 15 ) ( 0 ) ( 6 ) ( 10 ) ( 1 ) ( 13 ) ( 8 )
      ( 9 ) ( 4 ) ( 5 ) ( 11 ) ( 12 ) ( 7 ) ( 2 ) ( 14 ) ).

    mt_s5 = VALUE #(
      ( 2 ) ( 12 ) ( 4 ) ( 1 ) ( 7 ) ( 10 ) ( 11 ) ( 6 )
      ( 8 ) ( 5 ) ( 3 ) ( 15 ) ( 13 ) ( 0 ) ( 14 ) ( 9 )
      ( 14 ) ( 11 ) ( 2 ) ( 12 ) ( 4 ) ( 7 ) ( 13 ) ( 1 )
      ( 5 ) ( 0 ) ( 15 ) ( 10 ) ( 3 ) ( 9 ) ( 8 ) ( 6 )
      ( 4 ) ( 2 ) ( 1 ) ( 11 ) ( 10 ) ( 13 ) ( 7 ) ( 8 )
      ( 15 ) ( 9 ) ( 12 ) ( 5 ) ( 6 ) ( 3 ) ( 0 ) ( 14 )
      ( 11 ) ( 8 ) ( 12 ) ( 7 ) ( 1 ) ( 14 ) ( 2 ) ( 13 )
      ( 6 ) ( 15 ) ( 0 ) ( 9 ) ( 10 ) ( 4 ) ( 5 ) ( 3 ) ).

    mt_s6 = VALUE #(
      ( 12 ) ( 1 ) ( 10 ) ( 15 ) ( 9 ) ( 2 ) ( 6 ) ( 8 )
      ( 0 ) ( 13 ) ( 3 ) ( 4 ) ( 14 ) ( 7 ) ( 5 ) ( 11 )
      ( 10 ) ( 15 ) ( 4 ) ( 2 ) ( 7 ) ( 12 ) ( 9 ) ( 5 )
      ( 6 ) ( 1 ) ( 13 ) ( 14 ) ( 0 ) ( 11 ) ( 3 ) ( 8 )
      ( 9 ) ( 14 ) ( 15 ) ( 5 ) ( 2 ) ( 8 ) ( 12 ) ( 3 )
      ( 7 ) ( 0 ) ( 4 ) ( 10 ) ( 1 ) ( 13 ) ( 11 ) ( 6 )
      ( 4 ) ( 3 ) ( 2 ) ( 12 ) ( 9 ) ( 5 ) ( 15 ) ( 10 )
      ( 11 ) ( 14 ) ( 1 ) ( 7 ) ( 6 ) ( 0 ) ( 8 ) ( 13 ) ).

    mt_s7 = VALUE #(
      ( 4 ) ( 11 ) ( 2 ) ( 14 ) ( 15 ) ( 0 ) ( 8 ) ( 13 )
      ( 3 ) ( 12 ) ( 9 ) ( 7 ) ( 5 ) ( 10 ) ( 6 ) ( 1 )
      ( 13 ) ( 0 ) ( 11 ) ( 7 ) ( 4 ) ( 9 ) ( 1 ) ( 10 )
      ( 14 ) ( 3 ) ( 5 ) ( 12 ) ( 2 ) ( 15 ) ( 8 ) ( 6 )
      ( 1 ) ( 4 ) ( 11 ) ( 13 ) ( 12 ) ( 3 ) ( 7 ) ( 14 )
      ( 10 ) ( 15 ) ( 6 ) ( 8 ) ( 0 ) ( 5 ) ( 9 ) ( 2 )
      ( 6 ) ( 11 ) ( 13 ) ( 8 ) ( 1 ) ( 4 ) ( 10 ) ( 7 )
      ( 9 ) ( 5 ) ( 0 ) ( 15 ) ( 14 ) ( 2 ) ( 3 ) ( 12 ) ).

    mt_s8 = VALUE #(
      ( 13 ) ( 2 ) ( 8 ) ( 4 ) ( 6 ) ( 15 ) ( 11 ) ( 1 )
      ( 10 ) ( 9 ) ( 3 ) ( 14 ) ( 5 ) ( 0 ) ( 12 ) ( 7 )
      ( 1 ) ( 15 ) ( 13 ) ( 8 ) ( 10 ) ( 3 ) ( 7 ) ( 4 )
      ( 12 ) ( 5 ) ( 6 ) ( 11 ) ( 0 ) ( 14 ) ( 9 ) ( 2 )
      ( 7 ) ( 11 ) ( 4 ) ( 1 ) ( 9 ) ( 12 ) ( 14 ) ( 2 )
      ( 0 ) ( 6 ) ( 10 ) ( 13 ) ( 15 ) ( 3 ) ( 5 ) ( 8 )
      ( 2 ) ( 1 ) ( 14 ) ( 7 ) ( 4 ) ( 10 ) ( 8 ) ( 13 )
      ( 15 ) ( 12 ) ( 9 ) ( 0 ) ( 3 ) ( 5 ) ( 6 ) ( 11 ) ).

  ENDMETHOD.


  METHOD COLUMN.

    rv_column = 8 * iv_b+1(1) + 4 * iv_b+2(1) + 2 * iv_b+3(1) + iv_b+4(1).

    ASSERT rv_column >= 0.
    ASSERT rv_column <= 15.

  ENDMETHOD.


  METHOD C_AND_D.

    DATA: lv_shift TYPE i,
          lv_c_n   TYPE c LENGTH 28,
          lv_d_n   TYPE c LENGTH 28,
          lv_str   TYPE string.

    lv_c_n = iv_c_0.
    lv_d_n = iv_d_0.

    LOOP AT VALUE tty_itab(
        ( 1 ) ( 1 ) ( 2 ) ( 2 ) ( 2 ) ( 2 ) ( 2 ) ( 2 )
        ( 1 ) ( 2 ) ( 2 ) ( 2 ) ( 2 ) ( 2 ) ( 2 ) ( 1 ) ) INTO lv_shift.

      SHIFT lv_c_n LEFT BY lv_shift PLACES CIRCULAR.
      SHIFT lv_d_n LEFT BY lv_shift PLACES CIRCULAR.
      CONCATENATE lv_c_n lv_d_n INTO lv_str.
      APPEND lv_str TO rt_bits.

    ENDLOOP.

  ENDMETHOD.


  METHOD ENCRYPT.

* The MIT License (MIT)
*
* Copyright (c) 2015 Lars Hvam
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.

* https://www.utdallas.edu/~edsha/OS2000/des-algorithm-details.txt
* http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm

    DATA: lt_bits   TYPE string_table,
          lv_bits   TYPE string,
          lv_ip     TYPE c LENGTH 64,
          lv_k_plus TYPE c LENGTH 56.


* manipulate key
    lv_k_plus = permute_pc1( to_bits( iv_key ) ).
    lt_bits = c_and_d( iv_c_0 = lv_k_plus(28)
                       iv_d_0 = lv_k_plus+28(28) ).
    lt_bits = k( lt_bits ).

* data block
    lv_ip = permute_ip( to_bits( iv_plaintext ) ).
    lv_bits = l_and_r( iv_l_0 = lv_ip(32)
                       iv_r_0 = lv_ip+32(32)
                       it_k   = lt_bits ).
    rv_ciphertext = from_bits( lv_bits ).

  ENDMETHOD.


  METHOD F.

    DATA: lv_e   TYPE c LENGTH 48,
          lv_s   TYPE c LENGTH 32,
          lv_s1  TYPE c LENGTH 4,
          lv_s2  TYPE c LENGTH 4,
          lv_s3  TYPE c LENGTH 4,
          lv_s4  TYPE c LENGTH 4,
          lv_s5  TYPE c LENGTH 4,
          lv_s6  TYPE c LENGTH 4,
          lv_s7  TYPE c LENGTH 4,
          lv_s8  TYPE c LENGTH 4,
          lv_xor TYPE c LENGTH 48,
          lv_b1  TYPE c LENGTH 6,
          lv_b2  TYPE c LENGTH 6,
          lv_b3  TYPE c LENGTH 6,
          lv_b4  TYPE c LENGTH 6,
          lv_b5  TYPE c LENGTH 6,
          lv_b6  TYPE c LENGTH 6,
          lv_b7  TYPE c LENGTH 6,
          lv_b8  TYPE c LENGTH 6.


    lv_e = permute_e( iv_r ).

    lv_xor = xor( iv_a = lv_e
                  iv_b = iv_k ).

    lv_b1 = lv_xor(6).
    lv_xor = lv_xor+6.
    lv_b2 = lv_xor(6).
    lv_xor = lv_xor+6.
    lv_b3 = lv_xor(6).
    lv_xor = lv_xor+6.
    lv_b4 = lv_xor(6).
    lv_xor = lv_xor+6.
    lv_b5 = lv_xor(6).
    lv_xor = lv_xor+6.
    lv_b6 = lv_xor(6).
    lv_xor = lv_xor+6.
    lv_b7 = lv_xor(6).
    lv_xor = lv_xor+6.
    lv_b8 = lv_xor(6).
    lv_xor = lv_xor+6.

    lv_s1 = s1( lv_b1 ).
    lv_s2 = s2( lv_b2 ).
    lv_s3 = s3( lv_b3 ).
    lv_s4 = s4( lv_b4 ).
    lv_s5 = s5( lv_b5 ).
    lv_s6 = s6( lv_b6 ).
    lv_s7 = s7( lv_b7 ).
    lv_s8 = s8( lv_b8 ).

    CONCATENATE lv_s1 lv_s2 lv_s3 lv_s4 lv_s5 lv_s6 lv_s7 lv_s8 INTO lv_s.

    rv_res = permute_p( lv_s ).

  ENDMETHOD.


  METHOD FROM_BITS.

    DATA: lv_index TYPE i,
          lv_res   TYPE x LENGTH 8.


    ASSERT strlen( iv_bits ) = 64.

    DO 64 TIMES.
      lv_index = sy-index - 1.
      SET BIT lv_index + 1 OF lv_res TO iv_bits+lv_index(1).
    ENDDO.

    rv_xstr = lv_res.

  ENDMETHOD.


  METHOD I_TO_BITS_4.
    CONSTANTS lc_bits TYPE string VALUE '0000000100100011010001010110011110001001101010111100110111101111'.
    DATA lv_index TYPE i.

    lv_index = iv_i * 4.
    rv_bits = lc_bits+lv_index(4).

  ENDMETHOD.


  METHOD K.

    DATA: lv_bits LIKE LINE OF it_bits.


    DO 16 TIMES.
      READ TABLE it_bits INDEX sy-index INTO lv_bits.
      ASSERT sy-subrc = 0.
      lv_bits = permute_pc2( lv_bits ).
      APPEND lv_bits TO rt_bits.
    ENDDO.

  ENDMETHOD.


  METHOD L_AND_R.

    DATA: lv_l_prev TYPE c LENGTH 32,
          lv_r_prev TYPE c LENGTH 32,
          lv_l_n    TYPE c LENGTH 32,
          lv_r_n    TYPE c LENGTH 32,
          lv_k_n    TYPE c LENGTH 48,
          lv_t      TYPE c LENGTH 64.


    lv_l_prev = iv_l_0.
    lv_r_prev = iv_r_0.

    DO 16 TIMES.
      lv_l_n = lv_r_prev.
      READ TABLE it_k INDEX sy-index INTO lv_k_n.

      lv_r_n = xor( iv_a = lv_l_prev
                    iv_b = f( iv_r = lv_r_prev
                              iv_k = lv_k_n ) ).
      lv_l_prev = lv_l_n.
      lv_r_prev = lv_r_n.
    ENDDO.

    CONCATENATE lv_r_n lv_l_n INTO lv_t.

    rv_bits = permute_ip1( lv_t ).

  ENDMETHOD.


  METHOD PARITY_ADJUST.

    DATA: lv_input  TYPE c LENGTH 56,
          lv_output TYPE c LENGTH 64,
          lv_bits   TYPE c LENGTH 7,
          lv_offset TYPE i,
          lv_zeros  TYPE i.


    lv_input = to_bits( iv_byte7 ).

    DO 8 TIMES.
      lv_bits = lv_input(7).
      lv_input = lv_input+7.

      CONCATENATE lv_output lv_bits INTO lv_output.

      FIND ALL OCCURRENCES OF '0' IN lv_bits MATCH COUNT lv_zeros.
      IF lv_zeros MOD 2 = 0.
        CONCATENATE lv_output '0' INTO lv_output.
      ELSE.
        CONCATENATE lv_output '1' INTO lv_output.
      ENDIF.
    ENDDO.

    DO 64 TIMES.
      lv_offset = sy-index - 1.
      SET BIT sy-index OF rv_byte8 TO lv_output+lv_offset(1).
    ENDDO.

  ENDMETHOD.


  METHOD PERMUTE.
    DATA: lv_offset  TYPE i.

    LOOP AT it_permutation INTO lv_offset.

      lv_offset = lv_offset - 1.
      CONCATENATE rv_bits iv_bits+lv_offset(1) INTO rv_bits.

    ENDLOOP.

  ENDMETHOD.


  METHOD PERMUTE_E.
    rv_bits = permute( it_permutation = mt_e iv_bits = iv_bits ).
  ENDMETHOD.


  METHOD PERMUTE_IP.
    rv_bits = permute( it_permutation = mt_ip iv_bits = iv_bits ).
  ENDMETHOD.


  METHOD PERMUTE_IP1.
    rv_bits = permute( it_permutation = mt_ip1 iv_bits = iv_bits ).
  ENDMETHOD.


  METHOD PERMUTE_P.
    rv_bits = permute( it_permutation = mt_p iv_bits = iv_bits ).
  ENDMETHOD.


  METHOD PERMUTE_PC1.
    rv_bits = permute( it_permutation = mt_pc1 iv_bits = iv_bits ).
  ENDMETHOD.


  METHOD PERMUTE_PC2.
    rv_bits = permute( it_permutation = mt_pc2 iv_bits = iv_bits ).
  ENDMETHOD.


  METHOD ROW.

    rv_row = 2 * iv_b(1) + iv_b+5(1).

    ASSERT rv_row >= 0.
    ASSERT rv_row <= 3.

  ENDMETHOD.


  METHOD S1.

    DATA: lv_index TYPE i,
          lv_i     TYPE i.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE mt_s1 INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD S2.

    DATA: lv_index TYPE i,
          lv_i     TYPE i.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE mt_s2 INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD S3.

    DATA: lv_index TYPE i,
          lv_i     TYPE i.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE mt_s3 INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD S4.

    DATA: lv_index TYPE i,
          lv_i     TYPE i.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE mt_s4 INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD S5.

    DATA: lv_index TYPE i,
          lv_i     TYPE i.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE mt_s5 INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD S6.

    DATA: lv_index TYPE i,
          lv_i     TYPE i.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE mt_s6 INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD S7.

    DATA: lv_index TYPE i,
          lv_i     TYPE i.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE mt_s7 INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD S8.

    DATA: lv_index TYPE i,
          lv_i     TYPE i.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE mt_s8 INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD TO_BITS.

    DATA: lv_c      TYPE c LENGTH 1,
          lv_length TYPE i.


    lv_length = xstrlen( iv_binary ).
    lv_length = lv_length * 8.

    DO lv_length TIMES.
      GET BIT sy-index OF iv_binary INTO lv_c.
      CONCATENATE rv_bits lv_c INTO rv_bits.
    ENDDO.

  ENDMETHOD.


  METHOD XOR.

    DATA: lv_offset TYPE i.


    ASSERT strlen( iv_a ) = strlen( iv_b ).

    DO strlen( iv_a ) TIMES.
      lv_offset = sy-index - 1.

      IF iv_a+lv_offset(1) = iv_b+lv_offset(1).
        CONCATENATE rv_res '0' INTO rv_res.
      ELSE.
        CONCATENATE rv_res '1' INTO rv_res.
      ENDIF.
    ENDDO.

  ENDMETHOD.
ENDCLASS.
