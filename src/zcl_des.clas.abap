CLASS zcl_des DEFINITION
  PUBLIC
  CREATE PUBLIC .

  PUBLIC SECTION.
*"* public components of class ZCL_DES
*"* do not include other source files here!!!

    TYPES:
      ty_byte7 TYPE x LENGTH 7 .
    TYPES:
      ty_byte8 TYPE x LENGTH 8 .

    CLASS-METHODS decrypt
      IMPORTING
        !iv_key             TYPE ty_byte8
        !iv_ciphertext      TYPE xsequence
      RETURNING
        VALUE(rv_plaintext) TYPE xstring .
    CLASS-METHODS encrypt
      IMPORTING
        !iv_key              TYPE ty_byte8
        !iv_plaintext        TYPE xsequence
      RETURNING
        VALUE(rv_ciphertext) TYPE xstring .
    CLASS-METHODS parity_adjust
      IMPORTING
        !iv_byte7       TYPE ty_byte7
      RETURNING
        VALUE(rv_byte8) TYPE ty_byte8 .
  PROTECTED SECTION.
*"* protected components of class ZCL_DES
*"* do not include other source files here!!!

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
  PRIVATE SECTION.
*"* private components of class ZCL_DES
*"* do not include other source files here!!!
ENDCLASS.



CLASS ZCL_DES IMPLEMENTATION.


  METHOD column.

    CASE iv_b+1(4).
      WHEN '0000'.
        rv_column = 0.
      WHEN '0001'.
        rv_column = 1.
      WHEN '0010'.
        rv_column = 2.
      WHEN '0011'.
        rv_column = 3.
      WHEN '0100'.
        rv_column = 4.
      WHEN '0101'.
        rv_column = 5.
      WHEN '0110'.
        rv_column = 6.
      WHEN '0111'.
        rv_column = 7.
      WHEN '1000'.
        rv_column = 8.
      WHEN '1001'.
        rv_column = 9.
      WHEN '1010'.
        rv_column = 10.
      WHEN '1011'.
        rv_column = 11.
      WHEN '1100'.
        rv_column = 12.
      WHEN '1101'.
        rv_column = 13.
      WHEN '1110'.
        rv_column = 14.
      WHEN '1111'.
        rv_column = 15.
      WHEN OTHERS.
        ASSERT 1 = 1 + 1.
    ENDCASE.

  ENDMETHOD.


  METHOD c_and_d.

    DATA: lv_c_n TYPE c LENGTH 28,
          lv_d_n TYPE c LENGTH 28,
          lv_str TYPE string.

    DEFINE _shift.
      SHIFT lv_c_n LEFT BY &1 PLACES CIRCULAR.
      SHIFT lv_d_n LEFT BY &1 PLACES CIRCULAR.
      CONCATENATE lv_c_n lv_d_n INTO lv_str.
      APPEND lv_str TO rt_bits.
    END-OF-DEFINITION.


    lv_c_n = iv_c_0.
    lv_d_n = iv_d_0.

    _shift 1.
    _shift 1.
    _shift 2.
    _shift 2.
    _shift 2.
    _shift 2.
    _shift 2.
    _shift 2.
    _shift 1.
    _shift 2.
    _shift 2.
    _shift 2.
    _shift 2.
    _shift 2.
    _shift 2.
    _shift 1.

  ENDMETHOD.


  METHOD decrypt.

* todo
    RETURN.

  ENDMETHOD.


  METHOD encrypt.

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


  METHOD f.

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


  METHOD from_bits.

    DATA: lv_index TYPE i,
          lv_res   TYPE x LENGTH 8.


    ASSERT strlen( iv_bits ) = 64.

    DO 64 TIMES.
      lv_index = sy-index - 1.
      SET BIT lv_index + 1 OF lv_res TO iv_bits+lv_index(1).
    ENDDO.

    rv_xstr = lv_res.

  ENDMETHOD.


  METHOD i_to_bits_4.

    CASE iv_i.
      WHEN 0.
        rv_bits = '0000'.
      WHEN 1.
        rv_bits = '0001'.
      WHEN 2.
        rv_bits = '0010'.
      WHEN 3.
        rv_bits = '0011'.
      WHEN 4.
        rv_bits = '0100'.
      WHEN 5.
        rv_bits = '0101'.
      WHEN 6.
        rv_bits = '0110'.
      WHEN 7.
        rv_bits = '0111'.
      WHEN 8.
        rv_bits = '1000'.
      WHEN 9.
        rv_bits = '1001'.
      WHEN 10.
        rv_bits = '1010'.
      WHEN 11.
        rv_bits = '1011'.
      WHEN 12.
        rv_bits = '1100'.
      WHEN 13.
        rv_bits = '1101'.
      WHEN 14.
        rv_bits = '1110'.
      WHEN 15.
        rv_bits = '1111'.
      WHEN OTHERS.
        ASSERT 1 = 1 + 1.
    ENDCASE.

  ENDMETHOD.


  METHOD k.

    DATA: lv_bits LIKE LINE OF it_bits.


    DO 16 TIMES.
      READ TABLE it_bits INDEX sy-index INTO lv_bits.
      ASSERT sy-subrc = 0.
      lv_bits = permute_pc2( lv_bits ).
      APPEND lv_bits TO rt_bits.
    ENDDO.

  ENDMETHOD.


  METHOD l_and_r.

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


  METHOD parity_adjust.

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


  METHOD permute_e.

    DATA: lv_offset TYPE i.

    DEFINE _bit.
      lv_offset = &1 - 1.
      CONCATENATE rv_bits iv_bits+lv_offset(1) INTO rv_bits.
    END-OF-DEFINITION.


    _bit 32.
    _bit 1.
    _bit 2.
    _bit 3.
    _bit 4.
    _bit 5.
    _bit 4.
    _bit 5.
    _bit 6.
    _bit 7.
    _bit 8.
    _bit 9.
    _bit 8.
    _bit 9.
    _bit 10.
    _bit 11.
    _bit 12.
    _bit 13.
    _bit 12.
    _bit 13.
    _bit 14.
    _bit 15.
    _bit 16.
    _bit 17.
    _bit 16.
    _bit 17.
    _bit 18.
    _bit 19.
    _bit 20.
    _bit 21.
    _bit 20.
    _bit 21.
    _bit 22.
    _bit 23.
    _bit 24.
    _bit 25.
    _bit 24.
    _bit 25.
    _bit 26.
    _bit 27.
    _bit 28.
    _bit 29.
    _bit 28.
    _bit 29.
    _bit 30.
    _bit 31.
    _bit 32.
    _bit 1.

  ENDMETHOD.


  METHOD permute_ip.

    DATA: lv_offset TYPE i.

    DEFINE _bit.
      lv_offset = &1 - 1.
      CONCATENATE rv_bits iv_bits+lv_offset(1) INTO rv_bits.
    END-OF-DEFINITION.


    _bit 58.
    _bit 50.
    _bit 42.
    _bit 34.
    _bit 26.
    _bit 18.
    _bit 10.
    _bit 2.
    _bit 60.
    _bit 52.
    _bit 44.
    _bit 36.
    _bit 28.
    _bit 20.
    _bit 12.
    _bit 4.
    _bit 62.
    _bit 54.
    _bit 46.
    _bit 38.
    _bit 30.
    _bit 22.
    _bit 14.
    _bit 6.
    _bit 64.
    _bit 56.
    _bit 48.
    _bit 40.
    _bit 32.
    _bit 24.
    _bit 16.
    _bit 8.
    _bit 57.
    _bit 49.
    _bit 41.
    _bit 33.
    _bit 25.
    _bit 17.
    _bit 9.
    _bit 1.
    _bit 59.
    _bit 51.
    _bit 43.
    _bit 35.
    _bit 27.
    _bit 19.
    _bit 11.
    _bit 3.
    _bit 61.
    _bit 53.
    _bit 45.
    _bit 37.
    _bit 29.
    _bit 21.
    _bit 13.
    _bit 5.
    _bit 63.
    _bit 55.
    _bit 47.
    _bit 39.
    _bit 31.
    _bit 23.
    _bit 15.
    _bit 7.

  ENDMETHOD.


  METHOD permute_ip1.

    DATA: lv_offset TYPE i.

    DEFINE _bit.
      lv_offset = &1 - 1.
      CONCATENATE rv_bits iv_bits+lv_offset(1) INTO rv_bits.
    END-OF-DEFINITION.


    _bit 40.
    _bit 8.
    _bit 48.
    _bit 16.
    _bit 56.
    _bit 24.
    _bit 64.
    _bit 32.
    _bit 39.
    _bit 7.
    _bit 47.
    _bit 15.
    _bit 55.
    _bit 23.
    _bit 63.
    _bit 31.
    _bit 38.
    _bit 6.
    _bit 46.
    _bit 14.
    _bit 54.
    _bit 22.
    _bit 62.
    _bit 30.
    _bit 37.
    _bit 5.
    _bit 45.
    _bit 13.
    _bit 53.
    _bit 21.
    _bit 61.
    _bit 29.
    _bit 36.
    _bit 4.
    _bit 44.
    _bit 12.
    _bit 52.
    _bit 20.
    _bit 60.
    _bit 28.
    _bit 35.
    _bit 3.
    _bit 43.
    _bit 11.
    _bit 51.
    _bit 19.
    _bit 59.
    _bit 27.
    _bit 34.
    _bit 2.
    _bit 42.
    _bit 10.
    _bit 50.
    _bit 18.
    _bit 58.
    _bit 26.
    _bit 33.
    _bit 1.
    _bit 41.
    _bit 9.
    _bit 49.
    _bit 17.
    _bit 57.
    _bit 25.

  ENDMETHOD.


  METHOD permute_p.

    DATA: lv_offset TYPE i.

    DEFINE _bit.
      lv_offset = &1 - 1.
      CONCATENATE rv_bits iv_bits+lv_offset(1) INTO rv_bits.
    END-OF-DEFINITION.


    _bit 16.
    _bit 7.
    _bit 20.
    _bit 21.
    _bit 29.
    _bit 12.
    _bit 28.
    _bit 17.
    _bit 1.
    _bit 15.
    _bit 23.
    _bit 26.
    _bit 5.
    _bit 18.
    _bit 31.
    _bit 10.
    _bit 2.
    _bit 8.
    _bit 24.
    _bit 14.
    _bit 32.
    _bit 27.
    _bit 3.
    _bit 9.
    _bit 19.
    _bit 13.
    _bit 30.
    _bit 6.
    _bit 22.
    _bit 11.
    _bit 4.
    _bit 25.

  ENDMETHOD.


  METHOD permute_pc1.

    DATA: lv_offset TYPE i.

    DEFINE _bit.
      lv_offset = &1 - 1.
      CONCATENATE rv_bits iv_bits+lv_offset(1) INTO rv_bits.
    END-OF-DEFINITION.


    _bit 57.
    _bit 49.
    _bit 41.
    _bit 33.
    _bit 25.
    _bit 17.
    _bit 9.
    _bit 1.
    _bit 58.
    _bit 50.
    _bit 42.
    _bit 34.
    _bit 26.
    _bit 18.
    _bit 10.
    _bit 2.
    _bit 59.
    _bit 51.
    _bit 43.
    _bit 35.
    _bit 27.
    _bit 19.
    _bit 11.
    _bit 3.
    _bit 60.
    _bit 52.
    _bit 44.
    _bit 36.
    _bit 63.
    _bit 55.
    _bit 47.
    _bit 39.
    _bit 31.
    _bit 23.
    _bit 15.
    _bit 7.
    _bit 62.
    _bit 54.
    _bit 46.
    _bit 38.
    _bit 30.
    _bit 22.
    _bit 14.
    _bit 6.
    _bit 61.
    _bit 53.
    _bit 45.
    _bit 37.
    _bit 29.
    _bit 21.
    _bit 13.
    _bit 5.
    _bit 28.
    _bit 20.
    _bit 12.
    _bit 4.

  ENDMETHOD.


  METHOD permute_pc2.

    DATA: lv_offset TYPE i.

    DEFINE _bit.
      lv_offset = &1 - 1.
      CONCATENATE rv_bits iv_bits+lv_offset(1) INTO rv_bits.
    END-OF-DEFINITION.


    _bit 14.
    _bit 17.
    _bit 11.
    _bit 24.
    _bit 1.
    _bit 5.
    _bit 3.
    _bit 28.
    _bit 15.
    _bit 6.
    _bit 21.
    _bit 10.
    _bit 23.
    _bit 19.
    _bit 12.
    _bit 4.
    _bit 26.
    _bit 8.
    _bit 16.
    _bit 7.
    _bit 27.
    _bit 20.
    _bit 13.
    _bit 2.
    _bit 41.
    _bit 52.
    _bit 31.
    _bit 37.
    _bit 47.
    _bit 55.
    _bit 30.
    _bit 40.
    _bit 51.
    _bit 45.
    _bit 33.
    _bit 48.
    _bit 44.
    _bit 49.
    _bit 39.
    _bit 56.
    _bit 34.
    _bit 53.
    _bit 46.
    _bit 42.
    _bit 50.
    _bit 36.
    _bit 29.
    _bit 32.

  ENDMETHOD.


  METHOD row.

    DATA: lv_c TYPE c LENGTH 2.


    CONCATENATE iv_b(1) iv_b+5(1) INTO lv_c.
    CASE lv_c.
      WHEN '00'.
        rv_row = 0.
      WHEN '01'.
        rv_row = 1.
      WHEN '10'.
        rv_row = 2.
      WHEN '11'.
        rv_row = 3.
      WHEN OTHERS.
        ASSERT 1 = 1 + 1.
    ENDCASE.

  ENDMETHOD.


  METHOD s1.

    DATA: lt_table TYPE TABLE OF i,
          lv_index TYPE i,
          lv_i     TYPE i.


    APPEND 14 TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 13 TO lt_table.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE lt_table INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD s2.

    DATA: lt_table TYPE TABLE OF i,
          lv_index TYPE i,
          lv_i     TYPE i.


    APPEND 15 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 9  TO lt_table.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE lt_table INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD s3.

    DATA: lt_table TYPE TABLE OF i,
          lv_index TYPE i,
          lv_i     TYPE i.


    APPEND 10 TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 12 TO lt_table.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE lt_table INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD s4.

    DATA: lt_table TYPE TABLE OF i,
          lv_index TYPE i,
          lv_i     TYPE i.


    APPEND 7  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 14 TO lt_table.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE lt_table INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD s5.

    DATA: lt_table TYPE TABLE OF i,
          lv_index TYPE i,
          lv_i     TYPE i.


    APPEND 2  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 3  TO lt_table.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE lt_table INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD s6.

    DATA: lt_table TYPE TABLE OF i,
          lv_index TYPE i,
          lv_i     TYPE i.


    APPEND 12 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 13 TO lt_table.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE lt_table INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD s7.

    DATA: lt_table TYPE TABLE OF i,
          lv_index TYPE i,
          lv_i     TYPE i.


    APPEND 4  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 12 TO lt_table.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE lt_table INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD s8.

    DATA: lt_table TYPE TABLE OF i,
          lv_index TYPE i,
          lv_i     TYPE i.


    APPEND 13 TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 11 TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 2  TO lt_table.
    APPEND 1  TO lt_table.
    APPEND 14 TO lt_table.
    APPEND 7  TO lt_table.
    APPEND 4  TO lt_table.
    APPEND 10 TO lt_table.
    APPEND 8  TO lt_table.
    APPEND 13 TO lt_table.
    APPEND 15 TO lt_table.
    APPEND 12 TO lt_table.
    APPEND 9  TO lt_table.
    APPEND 0  TO lt_table.
    APPEND 3  TO lt_table.
    APPEND 5  TO lt_table.
    APPEND 6  TO lt_table.
    APPEND 11 TO lt_table.

    lv_index = ( row( iv_b ) * 16 ) + column( iv_b ) + 1.
    READ TABLE lt_table INDEX lv_index INTO lv_i.
    ASSERT sy-subrc = 0.
    rv_s = i_to_bits_4( lv_i ).

  ENDMETHOD.


  METHOD to_bits.

    DATA: lv_c      TYPE c LENGTH 1,
          lv_length TYPE i.


    lv_length = xstrlen( iv_binary ).
    lv_length = lv_length * 8.

    DO lv_length TIMES.
      GET BIT sy-index OF iv_binary INTO lv_c.
      CONCATENATE rv_bits lv_c INTO rv_bits.
    ENDDO.

  ENDMETHOD.


  METHOD xor.

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
