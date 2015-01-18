CLASS lcl_test DEFINITION DEFERRED.
CLASS zcl_md4 DEFINITION LOCAL FRIENDS lcl_test.

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
    METHODS: test1 FOR TESTING,
             test2 FOR TESTING,
             test3 FOR TESTING,
             test4 FOR TESTING,
             test5 FOR TESTING,
             test6 FOR TESTING,
             shift1 FOR TESTING.

ENDCLASS.       "lcl_Test

*----------------------------------------------------------------------*
*       CLASS lcl_Test IMPLEMENTATION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_test IMPLEMENTATION.
* ==============================

  METHOD test1.
* ===========

    DATA: lv_hash TYPE zcl_md4=>ty_byte16.


    lv_hash = zcl_md4=>hash( '' ). " empty string

    cl_abap_unit_assert=>assert_equals(
        exp = '31D6CFE0D16AE931B73C59D7E0C089C0'
        act = lv_hash ).

  ENDMETHOD.                    "test1

  METHOD test2.
* ===========

    DATA: lv_hash TYPE zcl_md4=>ty_byte16.


    lv_hash = zcl_md4=>hash( 'a' ).

    cl_abap_unit_assert=>assert_equals(
        exp = 'BDE52CB31DE33E46245E05FBDBD6FB24'
        act = lv_hash ).

  ENDMETHOD.                    "test1

  METHOD test3.
* ===========

    DATA: lv_hash TYPE zcl_md4=>ty_byte16.


    lv_hash = zcl_md4=>hash( 'abc' ).

    cl_abap_unit_assert=>assert_equals(
        exp = 'A448017AAF21D8525FC10AE87AA6729D'
        act = lv_hash ).

  ENDMETHOD.                    "test1

  METHOD test4.
* ===========

    DATA: lv_hash TYPE zcl_md4=>ty_byte16.


    lv_hash = zcl_md4=>hash( 'message digest' ).

    cl_abap_unit_assert=>assert_equals(
        exp = 'D9130A8164549FE818874806E1C7014B'
        act = lv_hash ).

  ENDMETHOD.                    "test1

  METHOD test5.
* ===========

    DATA: lv_hash TYPE zcl_md4=>ty_byte16.


    lv_hash = zcl_md4=>hash( 'abcdefghijklmnopqrstuvwxyz' ).

    cl_abap_unit_assert=>assert_equals(
        exp = 'D79E1C308AA5BBCDEEA8ED63DF412DA9'
        act = lv_hash ).

  ENDMETHOD.                    "test1

  METHOD test6.
* ===========

    DATA: lv_hash TYPE zcl_md4=>ty_byte16.


    lv_hash = zcl_md4=>hash( 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' ).

    cl_abap_unit_assert=>assert_equals(
        exp = '043F8582F241DB351CE627E153E7F0E4'
        act = lv_hash ).

  ENDMETHOD.                    "test1

  METHOD shift1.
* ===========

    DATA: lv_byte4 TYPE zcl_md4=>ty_byte4.


    lv_byte4 = zcl_md4=>shift(
        iv_input  = 'FFAA0033'
        iv_places = 1 ).

    cl_abap_unit_assert=>assert_equals(
        exp = 'FF540067'
        act = lv_byte4 ).

  ENDMETHOD.                    "shift1

ENDCLASS.       "lcl_Test