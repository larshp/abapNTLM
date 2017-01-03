CLASS lcl_test DEFINITION DEFERRED.
CLASS zcl_arc4 DEFINITION LOCAL FRIENDS lcl_test.

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

    METHODS: encrypt1 FOR TESTING RAISING cx_static_check,
             encrypt2 FOR TESTING RAISING cx_static_check,
             encrypt3 FOR TESTING RAISING cx_static_check,
             decrypt1 FOR TESTING RAISING cx_static_check,
             to_xstring FOR TESTING RAISING cx_static_check.

ENDCLASS.       "lcl_Test

*----------------------------------------------------------------------*
*       CLASS lcl_Test IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_test IMPLEMENTATION.
* ==============================

  METHOD to_xstring.
* ==============================

    DATA: lv_result TYPE xstring.


    lv_result = zcl_arc4=>to_xstring( 'Key' ).

    cl_abap_unit_assert=>assert_equals(
        exp = '4B6579'
        act = lv_result ).

  ENDMETHOD.       "string_To_Xstring_Utf8

  METHOD encrypt1.
* ==============================

    DATA: lv_ciphertext TYPE xstring.


    lv_ciphertext = zcl_arc4=>encrypt(
        iv_key       = 'Key'
        iv_plaintext = 'Plaintext' ).

    cl_abap_unit_assert=>assert_equals(
        exp = 'BBF316E8D940AF0AD3'
        act = lv_ciphertext ).

  ENDMETHOD.                    "encrypt

  METHOD encrypt2.
* ==============================

    DATA: lv_ciphertext TYPE xstring.


    lv_ciphertext = zcl_arc4=>encrypt(
        iv_key       = 'Wiki'
        iv_plaintext = 'pedia' ).

    cl_abap_unit_assert=>assert_equals(
        exp = '1021BF0420'
        act = lv_ciphertext ).

  ENDMETHOD.                    "encrypt2


  METHOD encrypt3.
* ==============================

    DATA: lv_ciphertext TYPE xstring.


    lv_ciphertext = zcl_arc4=>encrypt(
        iv_key       = 'Secret'
        iv_plaintext = 'Attack at dawn' ).

    cl_abap_unit_assert=>assert_equals(
        exp = '45A01F645FC35B383552544B9BF5'
        act = lv_ciphertext ).

  ENDMETHOD.                    "encrypt3

  METHOD decrypt1.
* ==============================

    CONSTANTS: lc_plaintext TYPE string VALUE 'Plaintext',
               lc_key       TYPE string VALUE 'Key'.

    DATA: lv_plaintext  TYPE string,
          lv_ciphertext TYPE xstring.


    lv_ciphertext = zcl_arc4=>encrypt(
        iv_key       = lc_key
        iv_plaintext = lc_plaintext ).

    lv_plaintext = zcl_arc4=>decrypt(
        iv_key        = lc_key
        iv_ciphertext = lv_ciphertext ).

    cl_abap_unit_assert=>assert_equals(
        exp = lc_plaintext
        act = lv_plaintext ).

  ENDMETHOD.                    "encrypt

ENDCLASS.       "lcl_Test