CLASS lcl_test DEFINITION DEFERRED.
CLASS zcl_ntlm_md4 DEFINITION LOCAL FRIENDS lcl_test.

*----------------------------------------------------------------------*
*       CLASS lcl_Test DEFINITION
*----------------------------------------------------------------------*
*
*----------------------------------------------------------------------*
CLASS lcl_test DEFINITION FOR TESTING INHERITING FROM lcl_bit_flipper
  DURATION SHORT
  RISK LEVEL HARMLESS
  FINAL.

  PRIVATE SECTION.

* ================
    METHODS:
      test1         FOR TESTING,
      test2         FOR TESTING,
      test3         FOR TESTING,
      test4         FOR TESTING,
      test5         FOR TESTING,
      test6         FOR TESTING,
      test7         FOR TESTING,
      buffer        FOR TESTING,
      barrel        FOR TESTING,
      barrel2       FOR TESTING,
      test_shift    FOR TESTING,
      test_overflow1 FOR TESTING,
      test_overflow2 FOR TESTING,
      test_overflow3 FOR TESTING,
      test_overflow4 FOR TESTING,
      test_overflow5 FOR TESTING,
      test_overflow6 FOR TESTING.

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

    DATA: lv_hash TYPE zcl_ntlm_md4=>ty_byte16.

    lv_hash = zcl_ntlm_md4=>hash( '' ). " empty string

    cl_abap_unit_assert=>assert_equals(
        exp = '31D6CFE0D16AE931B73C59D7E0C089C0'
        act = lv_hash ).

  ENDMETHOD.                    "test1

  METHOD test2.
* ===========

    DATA: lv_hash TYPE zcl_ntlm_md4=>ty_byte16.


    lv_hash = zcl_ntlm_md4=>hash( 'a' ).

    cl_abap_unit_assert=>assert_equals(
        exp = 'BDE52CB31DE33E46245E05FBDBD6FB24'
        act = lv_hash ).

  ENDMETHOD.                    "test1

  METHOD test3.
* ===========

    DATA: lv_hash TYPE zcl_ntlm_md4=>ty_byte16.


    lv_hash = zcl_ntlm_md4=>hash( 'abc' ).

    cl_abap_unit_assert=>assert_equals(
        exp = 'A448017AAF21D8525FC10AE87AA6729D'
        act = lv_hash ).

  ENDMETHOD.                    "test1

  METHOD test4.
* ===========

    DATA: lv_hash TYPE zcl_ntlm_md4=>ty_byte16.


    lv_hash = zcl_ntlm_md4=>hash( 'message digest' ).

    cl_abap_unit_assert=>assert_equals(
        exp = 'D9130A8164549FE818874806E1C7014B'
        act = lv_hash ).

  ENDMETHOD.                    "test1

  METHOD test5.
* ===========

    DATA: lv_hash TYPE zcl_ntlm_md4=>ty_byte16.


    lv_hash = zcl_ntlm_md4=>hash( 'abcdefghijklmnopqrstuvwxyz' ).

    cl_abap_unit_assert=>assert_equals(
        exp = 'D79E1C308AA5BBCDEEA8ED63DF412DA9'
        act = lv_hash ).

  ENDMETHOD.                    "test1

  METHOD test6.
* ===========

    DATA: lv_hash TYPE zcl_ntlm_md4=>ty_byte16.


    lv_hash = zcl_ntlm_md4=>hash(
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' ).

    cl_abap_unit_assert=>assert_equals(
        exp = '043F8582F241DB351CE627E153E7F0E4'
        act = lv_hash ).

  ENDMETHOD.                    "test1

  METHOD test7.
* ===========

    DATA: lv_hash TYPE zcl_ntlm_md4=>ty_byte16.

* 4103 = UTF-16LE Unicode
    lv_hash = zcl_ntlm_md4=>hash( iv_encoding = '4103'
                             iv_string   = 'SecREt01' ).

    cl_abap_unit_assert=>assert_equals(
        exp = 'CD06CA7C7E10C99B1D33B7485A2ED808'
        act = lv_hash ).

  ENDMETHOD.                    "test7

  METHOD test_shift.
* ===========

    DATA: lv_byte4  TYPE zcl_ntlm_md4=>ty_byte4.

    lv_byte4 = shift(
        iv_input  = 'FFAA0033'
        iv_places = 1 ).

    cl_abap_unit_assert=>assert_equals(
        exp = 'FF540067'
        act = lv_byte4 ).

  ENDMETHOD.                    "shift1

  METHOD buffer.
* ===========

    DATA: lv_word   TYPE zcl_ntlm_md4=>ty_byte4,
          lo_buffer TYPE REF TO lcl_buffer.

    lo_buffer = NEW lcl_buffer( zcl_ntlm_md4=>codepage( 'a' ) ).

    cl_abap_unit_assert=>assert_equals(
      exp  = 1
      act  = lo_buffer->get_blocks( )
      quit = if_aunit_constants=>no ).

    lo_buffer->set_block( 1 ).
    lv_word = lo_buffer->get_word( 0 ).

    cl_abap_unit_assert=>assert_equals(
      exp  = '00008061'
      act  = lv_word
      quit = if_aunit_constants=>no ).

    lo_buffer->set_block( 1 ).
    lv_word = lo_buffer->get_word( 14 ).

    cl_abap_unit_assert=>assert_equals(
      exp = '00000008'
      act = lv_word
      quit = if_aunit_constants=>no ).

    lo_buffer->set_block( 1 ).
    lv_word = lo_buffer->get_word( 15 ).

    cl_abap_unit_assert=>assert_equals(
      exp = '00000000'
      act = lv_word
      quit = if_aunit_constants=>no ).

    lo_buffer = NEW #( 'FF0000FF' ).
    lo_buffer->set_block( 1 ).
    lv_word = lo_buffer->get_word( 0 ).

    cl_abap_unit_assert=>assert_equals(
      exp  = 'FF0000FF'
      act  = lv_word
      quit = if_aunit_constants=>no ).

  ENDMETHOD.

  METHOD test_overflow1.

    DATA: lv_word TYPE zcl_ntlm_md4=>ty_byte4.

    lv_word = overflow( 2147483647 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '7FFFFFFF'
      act = lv_word ).

  ENDMETHOD.

  METHOD test_overflow2.

    DATA: lv_word TYPE zcl_ntlm_md4=>ty_byte4.

    lv_word = overflow( -2147483648 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '80000000'
      act = lv_word ).

  ENDMETHOD.

  METHOD test_overflow3.

    DATA: lv_word TYPE zcl_ntlm_md4=>ty_byte4.

    lv_word = overflow( 2147483647 + 1 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '80000000'
      act = lv_word ).

  ENDMETHOD.

  METHOD test_overflow4.

    DATA: lv_word TYPE zcl_ntlm_md4=>ty_byte4.

    lv_word = overflow( -2147483648 - 1 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '7FFFFFFF'
      act = lv_word ).

  ENDMETHOD.

  METHOD test_overflow5.

    DATA: lv_word TYPE zcl_ntlm_md4=>ty_byte4.

    lv_word = overflow( 2 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '00000002'
      act = lv_word ).

  ENDMETHOD.

  METHOD test_overflow6.

    DATA lv_word TYPE zcl_ntlm_md4=>ty_byte4.

    lv_word = overflow( 4 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '00000004'
      act = lv_word ).

  ENDMETHOD.

  METHOD barrel.

    DATA: lv_word   TYPE zcl_ntlm_md4=>ty_byte4,
          lo_barrel TYPE REF TO lcl_barrel.

    lo_barrel = NEW #( ).

    lo_barrel->reset( ).
    lv_word = lo_barrel->get( 0 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '67452301'
      act = lv_word
      quit = if_aunit_constants=>no ).

    lv_word = lo_barrel->get( 1 ).
    cl_abap_unit_assert=>assert_equals(
      exp = 'EFCDAB89'
      act = lv_word
      quit = if_aunit_constants=>no ).

    lv_word = lo_barrel->get( 2 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '98BADCFE'
      act = lv_word
      quit = if_aunit_constants=>no ).

    lv_word = lo_barrel->get( 3 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '10325476'
      act = lv_word
      quit = if_aunit_constants=>no ).

    lo_barrel->roll( ).

    lv_word = lo_barrel->get( 0 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '10325476'
      act = lv_word
      quit = if_aunit_constants=>no ).

    lo_barrel->roll( ).

    lv_word = lo_barrel->get( 0 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '98BADCFE'
      act = lv_word
      quit = if_aunit_constants=>no ).

    lo_barrel->roll( ).

    lv_word = lo_barrel->get( 0 ).
    cl_abap_unit_assert=>assert_equals(
      exp = 'EFCDAB89'
      act = lv_word
      quit = if_aunit_constants=>no ).

    lo_barrel->roll( ).

    lv_word = lo_barrel->get( 0 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '67452301'
      act = lv_word ).

    lo_barrel->reset( ).

    lo_barrel->roll( ).
    lo_barrel->set( '00000004' ).

    lv_word = lo_barrel->get( 0 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '00000004'
      act = lv_word ).

    lo_barrel->roll( ).
    lo_barrel->set( '00000003' ).

    lv_word = lo_barrel->get( 0 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '00000003'
      act = lv_word ).

    lo_barrel->roll( ).
    lo_barrel->set( '00000002' ).

    lv_word = lo_barrel->get( 0 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '00000002'
      act = lv_word ).

    lo_barrel->roll( ).
    lo_barrel->set( '00000001' ).

    lv_word = lo_barrel->get( 0 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '00000001'
      act = lv_word ).

    lo_barrel->snapshot( ).
    lo_barrel->accumulate( ).
    lo_barrel->reset( ).

    lv_word = lo_barrel->get( 0 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '00000002'
      act = lv_word ).

    lv_word = lo_barrel->get( 1 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '00000004'
      act = lv_word ).

    lv_word = lo_barrel->get( 2 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '00000006'
      act = lv_word ).

    lv_word = lo_barrel->get( 3 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '00000008'
      act = lv_word ).

    lo_barrel->snapshot( ).
    lo_barrel->set( 'FFFFFFFF' ).
    lo_barrel->accumulate( ).
    lv_word = lo_barrel->get( 0 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '00000001'
      act = lv_word ).

  ENDMETHOD.

  METHOD barrel2.

    DATA lv_word   TYPE zcl_ntlm_md4=>ty_byte4.
    DATA lo_barrel TYPE REF TO lcl_barrel.

    lo_barrel = NEW #( ).

    lo_barrel->set( '00000001' ).
    lo_barrel->roll( ).
    lo_barrel->set( '00000002' ).
    lo_barrel->roll( ).
    lo_barrel->set( '00000003' ).
    lo_barrel->roll( ).
    lo_barrel->set( '00000004' ).

    lo_barrel->snapshot( ).
    lo_barrel->accumulate( ).
    lo_barrel->reset( ).

    lv_word = lo_barrel->get( 1 ).
    cl_abap_unit_assert=>assert_equals(
      exp = '00000008'
      act = lv_word ).

  ENDMETHOD.

ENDCLASS.
