
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
* ================
    METHODS: parity_adjust FOR TESTING,
             encrypt FOR TESTING.

ENDCLASS.       "lcl_Test

*----------------------------------------------------------------------*
*       CLASS lcl_Test IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_test IMPLEMENTATION.
* ==============================

  METHOD encrypt.
* =====================

    DATA: lv_cipher TYPE xstring.


    lv_cipher = zcl_des=>encrypt(
      iv_key       = '133457799BBCDFF1'
      iv_plaintext = '0123456789ABCDEF' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = '85E813540F0AB405'
      act  = lv_cipher
      quit = if_aunit_constants=>no ).

    lv_cipher = zcl_des=>encrypt(
      iv_key       = 'CD83B34FC7F14392'
      iv_plaintext = '0123456789ABCDEF' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = '25A98C1C31E81847'
      act  = lv_cipher
      quit = if_aunit_constants=>no ).

    lv_cipher = zcl_des=>encrypt(
      iv_key       = '9B8F4C767543685D'
      iv_plaintext = '0123456789ABCDEF' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = '466B29B2DF4680F3'
      act  = lv_cipher
      quit = if_aunit_constants=>no ).

    lv_cipher = zcl_des=>encrypt(
      iv_key       = 'D904010101010101'
      iv_plaintext = '0123456789ABCDEF' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = '9958FB8C213A9CC6'
      act  = lv_cipher
      quit = if_aunit_constants=>no ).

  ENDMETHOD.                    "encrypt

  METHOD parity_adjust.
* =====================

    DATA: lv_word TYPE zcl_des=>ty_byte8.


    lv_word = zcl_des=>parity_adjust('CD06CA7C7E10C9' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = 'CD83B34FC7F14392'
      act  = lv_word
      quit = if_aunit_constants=>no ).

    lv_word = zcl_des=>parity_adjust('9B1D33B7485A2E' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = '9B8F4C767543685D'
      act  = lv_word
      quit = if_aunit_constants=>no ).

    lv_word = zcl_des=>parity_adjust('D8080000000000' ).
    cl_abap_unit_assert=>assert_equals(
      exp  = 'D904010101010101'
      act  = lv_word
      quit = if_aunit_constants=>no ).

  ENDMETHOD.       "parity_Adjust

ENDCLASS.       "lcl_Test
