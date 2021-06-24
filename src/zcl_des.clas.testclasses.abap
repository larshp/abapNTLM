CLASS lcl_test DEFINITION DEFERRED.
CLASS zcl_des DEFINITION LOCAL FRIENDS lcl_test.

*----------------------------------------------------------------------*
*       CLASS lcl_Test DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_test DEFINITION FOR TESTING
  DURATION SHORT
  RISK LEVEL HARMLESS
  FINAL.

  PRIVATE SECTION.
    METHODS parity_adjust FOR TESTING RAISING cx_static_check.
    METHODS encrypt1 FOR TESTING RAISING cx_static_check.
    METHODS encrypt2 FOR TESTING RAISING cx_static_check.
    METHODS encrypt3 FOR TESTING RAISING cx_static_check.
    METHODS encrypt4 FOR TESTING RAISING cx_static_check.
    METHODS to_bits FOR TESTING RAISING cx_static_check.
    METHODS permute_pc1 FOR TESTING RAISING cx_static_check.
    METHODS c_and_d FOR TESTING RAISING cx_static_check.
    METHODS permute_ip FOR TESTING RAISING cx_static_check.
    METHODS xor FOR TESTING RAISING cx_static_check.
    METHODS from_bits FOR TESTING RAISING cx_static_check.
    METHODS f FOR TESTING RAISING cx_static_check.

ENDCLASS.

*----------------------------------------------------------------------*
*       CLASS lcl_Test IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_test IMPLEMENTATION.

  METHOD f.

    DATA lv_res TYPE string.

    lv_res = zcl_des=>f(
      iv_r = '11110000101010101111000010101010'
      iv_k = '000110110000001011101111111111000111000001110010' ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_res
      exp = '00100011010010101010100110111011' ).

  ENDMETHOD.

  METHOD to_bits.

    DATA lv_bits TYPE string.

    lv_bits = zcl_des=>to_bits( '010203' ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_bits
      exp = '000000010000001000000011' ).

  ENDMETHOD.

  METHOD permute_pc1.

    DATA lv_bits TYPE string.

    lv_bits = zcl_des=>permute_pc1( '0001001100110100010101110111100110011011101111001101111111110001' ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_bits
      exp = '11110000110011001010101011110101010101100110011110001111' ).

  ENDMETHOD.

  METHOD c_and_d.

    DATA lt_bits TYPE string_table.
    DATA lv_str TYPE string.

    lt_bits = zcl_des=>c_and_d(
      iv_c_0  = '1111000011001100101010101111'
      iv_d_0  = '0101010101100110011110001111' ).

    cl_abap_unit_assert=>assert_equals(
      act = lines( lt_bits )
      exp = 16 ).

    LOOP AT lt_bits INTO lv_str.
      cl_abap_unit_assert=>assert_equals(
        act = strlen( lv_str )
        exp = 56 ).
    ENDLOOP.

  ENDMETHOD.

  METHOD permute_ip.

    DATA lv_bits TYPE string.

    lv_bits = zcl_des=>permute_ip( '0000000100100011010001010110011110001001101010111100110111101111' ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_bits
      exp = '1100110000000000110011001111111111110000101010101111000010101010' ).

  ENDMETHOD.

  METHOD from_bits.

    DATA lv_result TYPE xstring.

    lv_result = zcl_des=>from_bits( '1000010111101000000100110101010000001111000010101011010000000101' ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_result
      exp = '85E813540F0AB405' ).

  ENDMETHOD.

  METHOD xor.

    DATA lv_bits TYPE string.

    lv_bits = zcl_des=>xor(
      iv_a   = '011110100001010101010101011110100001010101010101'
      iv_b   = '000110110000001011101111111111000111000001110010' ).

    cl_abap_unit_assert=>assert_equals(
      act = lv_bits
      exp = '011000010001011110111010100001100110010100100111' ).

  ENDMETHOD.

  METHOD encrypt1.

    DATA: lv_cipher TYPE xstring.

    lv_cipher = zcl_des=>encrypt(
      iv_key       = '133457799BBCDFF1'
      iv_plaintext = '0123456789ABCDEF' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = '85E813540F0AB405'
      act  = lv_cipher ).

  ENDMETHOD.

  METHOD encrypt2.

    DATA: lv_cipher TYPE xstring.

    lv_cipher = zcl_des=>encrypt(
      iv_key       = 'CD83B34FC7F14392'
      iv_plaintext = '0123456789ABCDEF' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = '25A98C1C31E81847'
      act  = lv_cipher ).

  ENDMETHOD.

  METHOD encrypt3.

    DATA: lv_cipher TYPE xstring.

    lv_cipher = zcl_des=>encrypt(
      iv_key       = '9B8F4C767543685D'
      iv_plaintext = '0123456789ABCDEF' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = '466B29B2DF4680F3'
      act  = lv_cipher ).

  ENDMETHOD.

  METHOD encrypt4.

    DATA: lv_cipher TYPE xstring.

    lv_cipher = zcl_des=>encrypt(
      iv_key       = 'D904010101010101'
      iv_plaintext = '0123456789ABCDEF' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = '9958FB8C213A9CC6'
      act  = lv_cipher ).

  ENDMETHOD.

  METHOD parity_adjust.

    DATA: lv_word TYPE zcl_des=>ty_byte8.


    lv_word = zcl_des=>parity_adjust( 'CD06CA7C7E10C9' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = 'CD83B34FC7F14392'
      act  = lv_word
      quit = if_aunit_constants=>no ).

    lv_word = zcl_des=>parity_adjust( '9B1D33B7485A2E' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = '9B8F4C767543685D'
      act  = lv_word
      quit = if_aunit_constants=>no ).

    lv_word = zcl_des=>parity_adjust( 'D8080000000000' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = 'D904010101010101'
      act  = lv_word
      quit = if_aunit_constants=>no ).

  ENDMETHOD.

ENDCLASS.
