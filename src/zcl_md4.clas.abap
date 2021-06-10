CLASS zcl_md4 DEFINITION
  PUBLIC
  CREATE PUBLIC .

  PUBLIC SECTION.
*"* public components of class ZCL_MD4
*"* do not include other source files here!!!

    TYPES:
      ty_byte4 TYPE x LENGTH 4 .
    TYPES:
      ty_byte16 TYPE x LENGTH 16 .

    TYPE-POOLS abap .
    CLASS zcl_md4 DEFINITION LOAD .
    CLASS-METHODS hash
      IMPORTING
        !iv_string     TYPE clike
        !iv_encoding   TYPE abap_encoding DEFAULT 'UTF-8'
      RETURNING
        VALUE(rv_hash) TYPE ty_byte16 .
    CLASS-METHODS hash_hex
      IMPORTING
        !iv_xstr       TYPE xstring
      RETURNING
        VALUE(rv_hash) TYPE ty_byte16 .
  PROTECTED SECTION.
*"* protected components of class ZCL_MD4
*"* do not include other source files here!!!

    CLASS-METHODS overflow
      IMPORTING
        !iv_f         TYPE f
      RETURNING
        VALUE(rv_res) TYPE ty_byte4 .
    CLASS-METHODS shift
      IMPORTING
        !iv_input        TYPE ty_byte4
        !iv_places       TYPE i
      RETURNING
        VALUE(rv_output) TYPE ty_byte4 .
    CLASS-METHODS x
      IMPORTING
        !iv_xstr       TYPE xstring
        !iv_block      TYPE i
        !iv_word       TYPE i
      RETURNING
        VALUE(rv_word) TYPE ty_byte4 .
    CLASS-METHODS func_f
      IMPORTING
        !iv_x         TYPE ty_byte4
        !iv_y         TYPE ty_byte4
        !iv_z         TYPE ty_byte4
      RETURNING
        VALUE(rv_res) TYPE ty_byte4 .
    CLASS-METHODS func_ff
      IMPORTING
        !iv_a         TYPE ty_byte4
        !iv_b         TYPE ty_byte4
        !iv_c         TYPE ty_byte4
        !iv_d         TYPE ty_byte4
        !iv_x         TYPE ty_byte4
        !iv_s         TYPE i
      RETURNING
        VALUE(rv_res) TYPE ty_byte4 .
    CLASS-METHODS func_gg
      IMPORTING
        !iv_a         TYPE ty_byte4
        !iv_b         TYPE ty_byte4
        !iv_c         TYPE ty_byte4
        !iv_d         TYPE ty_byte4
        !iv_x         TYPE ty_byte4
        !iv_s         TYPE i
      RETURNING
        VALUE(rv_res) TYPE ty_byte4 .
    CLASS-METHODS func_hh
      IMPORTING
        !iv_a         TYPE ty_byte4
        !iv_b         TYPE ty_byte4
        !iv_c         TYPE ty_byte4
        !iv_d         TYPE ty_byte4
        !iv_x         TYPE ty_byte4
        !iv_s         TYPE i
      RETURNING
        VALUE(rv_res) TYPE ty_byte4 .
    CLASS-METHODS func_g
      IMPORTING
        !iv_x         TYPE ty_byte4
        !iv_y         TYPE ty_byte4
        !iv_z         TYPE ty_byte4
      RETURNING
        VALUE(rv_res) TYPE ty_byte4 .
    CLASS-METHODS func_h
      IMPORTING
        !iv_x         TYPE ty_byte4
        !iv_y         TYPE ty_byte4
        !iv_z         TYPE ty_byte4
      RETURNING
        VALUE(rv_res) TYPE ty_byte4 .
    CLASS-METHODS padding_length
      IMPORTING
        !iv_input         TYPE xstring
      RETURNING
        VALUE(rv_xstring) TYPE xstring .
    TYPE-POOLS abap .
    CLASS-METHODS codepage
      IMPORTING
        !iv_encoding      TYPE abap_encoding DEFAULT 'UTF-8'
        !iv_string        TYPE clike
      RETURNING
        VALUE(rv_xstring) TYPE xstring .
  PRIVATE SECTION.
*"* private components of class ZCL_MD4
*"* do not include other source files here!!!
ENDCLASS.



CLASS ZCL_MD4 IMPLEMENTATION.


  METHOD codepage.

    DATA: lo_obj TYPE REF TO cl_abap_conv_out_ce.


    lo_obj = cl_abap_conv_out_ce=>create( encoding = iv_encoding ).

    lo_obj->convert( EXPORTING
                       data = iv_string
                       n = strlen( iv_string )
                     IMPORTING buffer = rv_xstring ).

  ENDMETHOD.


  METHOD func_f.

* XY v not(X) Z

    rv_res = ( iv_x BIT-AND iv_y ) BIT-OR ( ( BIT-NOT iv_x ) BIT-AND iv_z ).

  ENDMETHOD.


  METHOD func_ff.

    DATA: lv_f TYPE f.

* (a + F(b,c,d) + X[k]) <<< s

    lv_f = iv_a +
      func_f( iv_x = iv_b
              iv_y = iv_c
              iv_z = iv_d ) +
      iv_x.
    rv_res = overflow( lv_f ).
    rv_res = shift( iv_input  = rv_res
                    iv_places = iv_s ).

  ENDMETHOD.


  METHOD func_g.

* XY v XZ v YZ

    rv_res = ( iv_x BIT-AND iv_y )
      BIT-OR ( iv_x BIT-AND iv_z )
      BIT-OR ( iv_y BIT-AND iv_z ).

  ENDMETHOD.


  METHOD func_gg.

    CONSTANTS: lc_add TYPE x LENGTH 4 VALUE '5A827999'.

    DATA: lv_f TYPE f.

* (a + G(b,c,d) + X[k] + 5A827999) <<< s

    lv_f = iv_a +
      func_g( iv_x = iv_b
              iv_y = iv_c
              iv_z = iv_d ) +
      iv_x + lc_add.
    rv_res = overflow( lv_f ).
    rv_res = shift( iv_input  = rv_res
                    iv_places = iv_s ).

  ENDMETHOD.


  METHOD func_h.

* X xor Y xor Z

    rv_res = ( iv_x BIT-XOR iv_y ) BIT-XOR iv_z.

  ENDMETHOD.


  METHOD func_hh.

    CONSTANTS: lc_add TYPE x LENGTH 4 VALUE '6ED9EBA1'.

    DATA: lv_f TYPE f.

* (a + H(b,c,d) + X[k] + 6ED9EBA1) <<< s

    lv_f = iv_a +
      func_h( iv_x = iv_b
              iv_y = iv_c
              iv_z = iv_d ) +
      iv_x + lc_add.
    rv_res = overflow( lv_f ).
    rv_res = shift( iv_input  = rv_res
                    iv_places = iv_s ).

  ENDMETHOD.


  METHOD hash.

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

* http://tools.ietf.org/html/rfc1320

    DATA: lv_xstr TYPE xstring.


    lv_xstr = codepage( iv_encoding = iv_encoding
                        iv_string   = iv_string ).

    rv_hash = hash_hex( lv_xstr ).

  ENDMETHOD.


  METHOD hash_hex.

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

    DATA: lv_xstr TYPE xstring.

* big endian
    DATA: lv_a TYPE x LENGTH 4 VALUE '67452301',
          lv_b TYPE x LENGTH 4 VALUE 'EFCDAB89',
          lv_c TYPE x LENGTH 4 VALUE '98BADCFE',
          lv_d TYPE x LENGTH 4 VALUE '10325476'.

    DATA: lv_aa TYPE x LENGTH 4,
          lv_bb TYPE x LENGTH 4,
          lv_cc TYPE x LENGTH 4,
          lv_dd TYPE x LENGTH 4.

    DATA: lv_x     TYPE ty_byte4,
          lv_f     TYPE f,
          lv_block TYPE i.

    DEFINE _ff.
      lv_x = x(
          iv_xstr  = lv_xstr
          iv_block = lv_block
          iv_word  = &5 ).
      &1 = func_ff(
        iv_a   = &1
        iv_b   = &2
        iv_c   = &3
        iv_d   = &4
        iv_x   = lv_x
        iv_s   = &6 ).
    END-OF-DEFINITION.

    DEFINE _gg.
      lv_x = x(
          iv_xstr  = lv_xstr
          iv_block = lv_block
          iv_word  = &5 ).
      &1 = func_gg(
        iv_a   = &1
        iv_b   = &2
        iv_c   = &3
        iv_d   = &4
        iv_x   = lv_x
        iv_s   = &6 ).
    END-OF-DEFINITION.

    DEFINE _hh.
      lv_x = x(
          iv_xstr  = lv_xstr
          iv_block = lv_block
          iv_word  = &5 ).
      &1 = func_hh(
        iv_a   = &1
        iv_b   = &2
        iv_c   = &3
        iv_d   = &4
        iv_x   = lv_x
        iv_s   = &6 ).
    END-OF-DEFINITION.


    lv_xstr = padding_length( iv_xstr ).

* 16 words = 64 byte
    DO xstrlen( lv_xstr ) / 64 TIMES.
      lv_block = sy-index.

      lv_aa = lv_a.
      lv_bb = lv_b.
      lv_cc = lv_c.
      lv_dd = lv_d.

* round 1
      _ff lv_a lv_b lv_c lv_d  0  3.
      _ff lv_d lv_a lv_b lv_c  1  7.
      _ff lv_c lv_d lv_a lv_b  2 11.
      _ff lv_b lv_c lv_d lv_a  3 19.
      _ff lv_a lv_b lv_c lv_d  4  3.
      _ff lv_d lv_a lv_b lv_c  5  7.
      _ff lv_c lv_d lv_a lv_b  6 11.
      _ff lv_b lv_c lv_d lv_a  7 19.
      _ff lv_a lv_b lv_c lv_d  8  3.
      _ff lv_d lv_a lv_b lv_c  9  7.
      _ff lv_c lv_d lv_a lv_b 10 11.
      _ff lv_b lv_c lv_d lv_a 11 19.
      _ff lv_a lv_b lv_c lv_d 12  3.
      _ff lv_d lv_a lv_b lv_c 13  7.
      _ff lv_c lv_d lv_a lv_b 14 11.
      _ff lv_b lv_c lv_d lv_a 15 19.

* round 2
      _gg lv_a lv_b lv_c lv_d  0  3.
      _gg lv_d lv_a lv_b lv_c  4  5.
      _gg lv_c lv_d lv_a lv_b  8  9.
      _gg lv_b lv_c lv_d lv_a 12 13.
      _gg lv_a lv_b lv_c lv_d  1  3.
      _gg lv_d lv_a lv_b lv_c  5  5.
      _gg lv_c lv_d lv_a lv_b  9  9.
      _gg lv_b lv_c lv_d lv_a 13 13.
      _gg lv_a lv_b lv_c lv_d  2  3.
      _gg lv_d lv_a lv_b lv_c  6  5.
      _gg lv_c lv_d lv_a lv_b 10  9.
      _gg lv_b lv_c lv_d lv_a 14 13.
      _gg lv_a lv_b lv_c lv_d  3  3.
      _gg lv_d lv_a lv_b lv_c  7  5.
      _gg lv_c lv_d lv_a lv_b 11  9.
      _gg lv_b lv_c lv_d lv_a 15 13.

* round 3
      _hh lv_a lv_b lv_c lv_d  0  3.
      _hh lv_d lv_a lv_b lv_c  8  9.
      _hh lv_c lv_d lv_a lv_b  4 11.
      _hh lv_b lv_c lv_d lv_a 12 15.
      _hh lv_a lv_b lv_c lv_d  2  3.
      _hh lv_d lv_a lv_b lv_c 10  9.
      _hh lv_c lv_d lv_a lv_b  6 11.
      _hh lv_b lv_c lv_d lv_a 14 15.
      _hh lv_a lv_b lv_c lv_d  1  3.
      _hh lv_d lv_a lv_b lv_c  9  9.
      _hh lv_c lv_d lv_a lv_b  5 11.
      _hh lv_b lv_c lv_d lv_a 13 15.
      _hh lv_a lv_b lv_c lv_d  3  3.
      _hh lv_d lv_a lv_b lv_c 11  9.
      _hh lv_c lv_d lv_a lv_b  7 11.
      _hh lv_b lv_c lv_d lv_a 15 15.

      lv_f = lv_a + lv_aa.
      lv_a = overflow( lv_f ).
      lv_f = lv_b + lv_bb.
      lv_b = overflow( lv_f ).
      lv_f = lv_c + lv_cc.
      lv_c = overflow( lv_f ).
      lv_f = lv_d + lv_dd.
      lv_d = overflow( lv_f ).
    ENDDO.

    CONCATENATE
      lv_a+3(1) lv_a+2(1) lv_a+1(1) lv_a(1)
      lv_b+3(1) lv_b+2(1) lv_b+1(1) lv_b(1)
      lv_c+3(1) lv_c+2(1) lv_c+1(1) lv_c(1)
      lv_d+3(1) lv_d+2(1) lv_d+1(1) lv_d(1)
      INTO rv_hash IN BYTE MODE.

  ENDMETHOD.


  METHOD overflow.

    DATA: lv_f      TYPE f,
          lv_maxint TYPE i.


    lv_maxint = 2 ** 31 - 1.

    lv_f = iv_f.
    IF iv_f < - lv_maxint OR iv_f > lv_maxint.
      lv_f = ( iv_f + ( lv_maxint + 1 ) ) MOD ( 2 * ( lv_maxint + 1 ) ) - lv_maxint - 1.
    ENDIF.

    rv_res = lv_f.

  ENDMETHOD.


  METHOD padding_length.

    CONSTANTS: lc_x0 TYPE x LENGTH 1 VALUE '00',
               lc_x1 TYPE x LENGTH 1 VALUE '80'.

    DATA: lv_length TYPE x LENGTH 8. " double word


    CONCATENATE iv_input lc_x1 INTO rv_xstring IN BYTE MODE.

    WHILE xstrlen( rv_xstring ) MOD 64 <> 56.
      CONCATENATE rv_xstring lc_x0 INTO rv_xstring IN BYTE MODE.
    ENDWHILE.

    lv_length = xstrlen( iv_input ) * 8. " get number of bits
    CONCATENATE rv_xstring
      lv_length+7(1) lv_length+6(1) lv_length+5(1) lv_length+4(1)
      lv_length+3(1) lv_length+2(1) lv_length+1(1) lv_length(1)
      INTO rv_xstring IN BYTE MODE.

  ENDMETHOD.


  METHOD shift.

    DATA: lv_bits   TYPE c LENGTH 32,
          lv_offset TYPE i,
          lv_bit    TYPE c LENGTH 1.


    DO 32 TIMES.
      GET BIT sy-index OF iv_input INTO lv_bit.
      CONCATENATE lv_bits lv_bit INTO lv_bits.
    ENDDO.

    SHIFT lv_bits LEFT CIRCULAR BY iv_places PLACES.

    DO 32 TIMES.
      lv_offset = sy-index - 1.
      lv_bit = lv_bits+lv_offset(1).
      SET BIT lv_offset + 1 OF rv_output TO lv_bit.
    ENDDO.

  ENDMETHOD.


  METHOD x.

    DATA: lv_offset TYPE i,
          lv_x      TYPE x.


    lv_offset = ( ( iv_block - 1 ) * 16 + iv_word ) * 4.

    DO 4 TIMES.
      lv_x = iv_xstr+lv_offset(1).
      CONCATENATE lv_x rv_word INTO rv_word IN BYTE MODE.
      lv_offset = lv_offset + 1.
    ENDDO.

  ENDMETHOD.
ENDCLASS.
