class ZCL_DES definition
  public
  create public .

public section.
*"* public components of class ZCL_DES
*"* do not include other source files here!!!

  types:
    TY_BYTE7 type x length 7 .
  types:
    TY_BYTE8 type x length 8 .

  class-methods ENCRYPT
    importing
      !IV_KEY type TY_BYTE8
      !IV_PLAINTEXT type XSTRING
    returning
      value(RV_CIPHERTEXT) type XSTRING .
  class-methods PARITY_ADJUST
    importing
      !IV_BYTE7 type TY_BYTE7
    returning
      value(RV_BYTE8) type TY_BYTE8 .
protected section.
*"* protected components of class ZCL_DES
*"* do not include other source files here!!!

  class-methods XOR
    importing
      !IV_A type CLIKE
      !IV_B type CLIKE
    returning
      value(RV_RES) type STRING .
  class-methods TO_BITS
    importing
      !IV_BINARY type XSEQUENCE
    returning
      value(RV_BITS) type STRING .
  class-methods S8
    importing
      !IV_B type CLIKE
    returning
      value(RV_S) type STRING .
  class-methods S7
    importing
      !IV_B type CLIKE
    returning
      value(RV_S) type STRING .
  class-methods S6
    importing
      !IV_B type CLIKE
    returning
      value(RV_S) type STRING .
  class-methods S5
    importing
      !IV_B type CLIKE
    returning
      value(RV_S) type STRING .
  class-methods S4
    importing
      !IV_B type CLIKE
    returning
      value(RV_S) type STRING .
  class-methods S3
    importing
      !IV_B type CLIKE
    returning
      value(RV_S) type STRING .
  class-methods S2
    importing
      !IV_B type CLIKE
    returning
      value(RV_S) type STRING .
  class-methods S1
    importing
      !IV_B type CLIKE
    returning
      value(RV_S) type STRING .
  class-methods ROW
    importing
      !IV_B type CLIKE
    returning
      value(RV_ROW) type I .
  class-methods PERMUTE_PC2
    importing
      !IV_BITS type CLIKE
    returning
      value(RV_BITS) type STRING .
  class-methods PERMUTE_PC1
    importing
      !IV_BITS type CLIKE
    returning
      value(RV_BITS) type STRING .
  class-methods PERMUTE_P
    importing
      !IV_BITS type CLIKE
    returning
      value(RV_BITS) type STRING .
  class-methods PERMUTE_IP1
    importing
      !IV_BITS type CLIKE
    returning
      value(RV_BITS) type STRING .
  class-methods PERMUTE_IP
    importing
      !IV_BITS type CLIKE
    returning
      value(RV_BITS) type STRING .
  class-methods PERMUTE_E
    importing
      !IV_BITS type CLIKE
    returning
      value(RV_BITS) type STRING .
  class-methods L_AND_R
    importing
      !IV_L_0 type CLIKE
      !IV_R_0 type CLIKE
      !IT_K type STRING_TT
    returning
      value(RV_BITS) type STRING .
  class-methods K
    importing
      !IT_BITS type STRING_TT
    returning
      value(RT_BITS) type STRING_TT .
  class-methods I_TO_BITS_4
    importing
      !IV_I type I
    returning
      value(RV_BITS) type STRING .
  class-methods FROM_BITS
    importing
      !IV_BITS type CLIKE
    returning
      value(RV_XSTR) type XSTRING .
  class-methods F
    importing
      !IV_R type CLIKE
      !IV_K type CLIKE
    returning
      value(RV_RES) type STRING .
  class-methods C_AND_D
    importing
      !IV_C_0 type CLIKE
      !IV_D_0 type CLIKE
    returning
      value(RT_BITS) type STRING_TT .
  class-methods COLUMN
    importing
      !IV_B type CLIKE
    returning
      value(RV_COLUMN) type I .
private section.
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
    shift lv_c_n left by &1 places circular.
    shift lv_d_n left by &1 places circular.
    concatenate lv_c_n lv_d_n into lv_str.
    append lv_str to rt_bits.
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

  DATA: lt_bits   TYPE string_tt,
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
        lv_res TYPE x LENGTH 8.


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


METHOD PERMUTE_E.

  DATA: lv_offset TYPE i.

  DEFINE _bit.
    lv_offset = &1 - 1.
    concatenate rv_bits iv_bits+lv_offset(1) into rv_bits.
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
    concatenate rv_bits iv_bits+lv_offset(1) into rv_bits.
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


METHOD PERMUTE_IP1.

  DATA: lv_offset TYPE i.

  DEFINE _bit.
    lv_offset = &1 - 1.
    concatenate rv_bits iv_bits+lv_offset(1) into rv_bits.
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
    concatenate rv_bits iv_bits+lv_offset(1) into rv_bits.
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
    concatenate rv_bits iv_bits+lv_offset(1) into rv_bits.
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
    concatenate rv_bits iv_bits+lv_offset(1) into rv_bits.
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