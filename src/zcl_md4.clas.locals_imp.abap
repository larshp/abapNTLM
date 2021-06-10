*"* use this source file for the definition and implementation of
*"* local helper classes, interface definitions and type
*"* declarations


CLASS lcl_bit_flipper DEFINITION.

  PROTECTED SECTION.

    METHODS:
      overflow
        IMPORTING
          iv_f             TYPE f
        RETURNING
          VALUE(rv_result) TYPE zcl_md4=>ty_byte4,
      shift
        IMPORTING
          iv_input         TYPE zcl_md4=>ty_byte4
          iv_places        TYPE i
        RETURNING
          VALUE(rv_result) TYPE zcl_md4=>ty_byte4.

ENDCLASS.


CLASS lcl_barrel DEFINITION.

  PUBLIC SECTION.

    METHODS:
      constructor,
      reset,
      roll,
      set IMPORTING iv_word TYPE zcl_md4=>ty_byte4,
      get
        IMPORTING iv_index         TYPE i
        RETURNING VALUE(rv_result) TYPE zcl_md4=>ty_byte4,
      snapshot,
      accumulate,
      get_hash RETURNING VALUE(rv_result) TYPE zcl_md4=>ty_byte16.

  PRIVATE SECTION.

    DATA:
      mt_barrel     TYPE STANDARD TABLE OF zcl_md4=>ty_byte4,
      mt_old_barrel TYPE STANDARD TABLE OF zcl_md4=>ty_byte4,
      mv_index      TYPE i.

    METHODS:
      overflow
        IMPORTING
          iv_f             TYPE f
        RETURNING
          VALUE(rv_result) TYPE zcl_md4=>ty_byte4.

ENDCLASS.


CLASS lcl_buffer DEFINITION INHERITING FROM lcl_bit_flipper.

  PUBLIC SECTION.

    METHODS:
      constructor IMPORTING iv_xstr TYPE xstring,
      set_block IMPORTING iv_block TYPE i,
      get_word IMPORTING iv_word TYPE i RETURNING VALUE(rv_result) TYPE zcl_md4=>ty_byte4,
      get_blocks RETURNING VALUE(rv_result) TYPE i.

  PRIVATE SECTION.

    DATA:
      mv_buffer TYPE xstring,
      mv_block  TYPE i.

ENDCLASS.


CLASS lcl_hasher DEFINITION ABSTRACT INHERITING FROM lcl_bit_flipper.

  PUBLIC SECTION.
    TYPES:
      BEGIN OF ty_hash_def,
        word  TYPE i,
        shift TYPE i,
      END OF ty_hash_def.

    METHODS:
      constructor
        IMPORTING
          io_buffer TYPE REF TO lcl_buffer
          io_barrel TYPE REF TO lcl_barrel,
      hash.


  PROTECTED SECTION.

    DATA:
      mo_buffer   TYPE REF TO lcl_buffer,
      mo_barrel   TYPE REF TO lcl_barrel,
      mt_hash_def TYPE STANDARD TABLE OF ty_hash_def,
      mv_add      TYPE x LENGTH 4.


    METHODS:
      hash_function
        IMPORTING
          is_def           TYPE ty_hash_def
        RETURNING
          VALUE(rv_result) TYPE zcl_md4=>ty_byte4,
      func ABSTRACT
        IMPORTING
          iv_x             TYPE zcl_md4=>ty_byte4
          iv_y             TYPE zcl_md4=>ty_byte4
          iv_z             TYPE zcl_md4=>ty_byte4
        RETURNING
          VALUE(rv_result) TYPE zcl_md4=>ty_byte4.

ENDCLASS.


CLASS lcl_ff DEFINITION INHERITING FROM lcl_hasher.

  PUBLIC SECTION.

    METHODS:
      constructor
        IMPORTING
          io_buffer TYPE REF TO lcl_buffer
          io_barrel TYPE REF TO lcl_barrel.

  PROTECTED SECTION.

    METHODS:
      func REDEFINITION.

ENDCLASS.


CLASS lcl_gg DEFINITION INHERITING FROM lcl_hasher.

  PUBLIC SECTION.

    METHODS:
      constructor
        IMPORTING
          io_buffer TYPE REF TO lcl_buffer
          io_barrel TYPE REF TO lcl_barrel.

  PROTECTED SECTION.

    METHODS:
      func REDEFINITION.

ENDCLASS.


CLASS lcl_hh DEFINITION INHERITING FROM lcl_hasher.

  PUBLIC SECTION.

    METHODS:
      constructor
        IMPORTING
          io_buffer TYPE REF TO lcl_buffer
          io_barrel TYPE REF TO lcl_barrel.

  PROTECTED SECTION.

    METHODS:
      func REDEFINITION.

ENDCLASS.


CLASS lcl_bit_flipper IMPLEMENTATION.

  METHOD overflow.
    DATA: lv_f      TYPE f,
          lv_maxint TYPE i.

    lv_maxint = 2 ** 31 - 1.

    lv_f = iv_f.
    IF iv_f < - lv_maxint OR iv_f > lv_maxint.
      lv_f = ( iv_f + ( lv_maxint + 1 ) ) MOD ( 2 * ( lv_maxint + 1 ) ) - lv_maxint - 1.
    ENDIF.

    rv_result = lv_f.

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
      SET BIT lv_offset + 1 OF rv_result TO lv_bit.
    ENDDO.

  ENDMETHOD.

ENDCLASS.


CLASS lcl_barrel IMPLEMENTATION.

  METHOD constructor.
* big endian
    APPEND '67452301' TO mt_barrel.
    APPEND 'EFCDAB89' TO mt_barrel.
    APPEND '98BADCFE' TO mt_barrel.
    APPEND '10325476' TO mt_barrel.
    mv_index = 0.
  ENDMETHOD.

  METHOD reset.
    mv_index = 0.
  ENDMETHOD.

  METHOD roll.
    mv_index = ( mv_index + lines( mt_barrel ) - 1 )  MOD lines( mt_barrel ).
  ENDMETHOD.

  METHOD set.
    FIELD-SYMBOLS:
      <word> TYPE zcl_md4=>ty_byte4.

    READ TABLE mt_barrel
      INDEX mv_index + 1
      ASSIGNING <word>.

    IF sy-subrc = 0.
      <word> = iv_word.
    ENDIF.
  ENDMETHOD.

  METHOD get.
    DATA:
      lv_index TYPE i.
    FIELD-SYMBOLS:
      <word> TYPE zcl_md4=>ty_byte4.

    lv_index = ( mv_index + iv_index ) MOD lines( mt_barrel ).

    READ TABLE mt_barrel
      INDEX lv_index + 1
      ASSIGNING <word>.

    IF sy-subrc = 0.
      rv_result = <word>.
    ENDIF.
  ENDMETHOD.

  METHOD snapshot.
    CLEAR mt_old_barrel.
    APPEND LINES OF mt_barrel TO mt_old_barrel.
  ENDMETHOD.

  METHOD accumulate.
    DATA:
      lv_f TYPE f.

    reset( ).

    DO lines( mt_barrel ) TIMES.
      lv_f = mt_barrel[ mv_index + 1 ] + mt_old_barrel[ mv_index + 1 ].
      set( overflow( lv_f ) ).
      roll( ).
    ENDDO.

  ENDMETHOD.

  METHOD overflow.
    DATA: lv_f      TYPE f,
          lv_maxint TYPE i.

    lv_maxint = 2 ** 31 - 1.

    lv_f = iv_f.
    IF iv_f < - lv_maxint OR iv_f > lv_maxint.
      lv_f = ( iv_f + ( lv_maxint + 1 ) ) MOD ( 2 * ( lv_maxint + 1 ) ) - lv_maxint - 1.
    ENDIF.

    rv_result = lv_f.

  ENDMETHOD.

  METHOD get_hash.
    DATA:
      lv_a TYPE zcl_md4=>ty_byte4,
      lv_b TYPE zcl_md4=>ty_byte4,
      lv_c TYPE zcl_md4=>ty_byte4,
      lv_d TYPE zcl_md4=>ty_byte4.

    reset( ).
    lv_a = get( 0 ).
    lv_b = get( 1 ).
    lv_c = get( 2 ).
    lv_d = get( 3 ).

    CONCATENATE
      lv_a+3(1) lv_a+2(1) lv_a+1(1) lv_a(1)
      lv_b+3(1) lv_b+2(1) lv_b+1(1) lv_b(1)
      lv_c+3(1) lv_c+2(1) lv_c+1(1) lv_c(1)
      lv_d+3(1) lv_d+2(1) lv_d+1(1) lv_d(1)
      INTO rv_result IN BYTE MODE.
  ENDMETHOD.

ENDCLASS.


CLASS lcl_buffer IMPLEMENTATION.

  METHOD constructor.
    super->constructor( ).

    mv_buffer = iv_xstr.

    CONSTANTS: lc_x0 TYPE x LENGTH 1 VALUE '00',
               lc_x1 TYPE x LENGTH 1 VALUE '80'.

    DATA: lv_length TYPE x LENGTH 8. " double word


    CONCATENATE iv_xstr lc_x1 INTO mv_buffer IN BYTE MODE.

    WHILE xstrlen( mv_buffer ) MOD 64 <> 56.
      CONCATENATE mv_buffer lc_x0 INTO mv_buffer IN BYTE MODE.
    ENDWHILE.

    lv_length = xstrlen( iv_xstr ) * 8. " get number of bits
    CONCATENATE mv_buffer
      lv_length+7(1) lv_length+6(1) lv_length+5(1) lv_length+4(1)
      lv_length+3(1) lv_length+2(1) lv_length+1(1) lv_length(1)
      INTO mv_buffer IN BYTE MODE.
  ENDMETHOD.

  METHOD set_block.
    mv_block = iv_block.
  ENDMETHOD.

  METHOD get_word.
    DATA:
      lv_offset TYPE i,
      lv_x      TYPE x.

    lv_offset = ( ( mv_block - 1 ) * 16 + iv_word ) * 4.

    DO 4 TIMES.
      lv_x = mv_buffer+lv_offset(1).
      CONCATENATE lv_x rv_result INTO rv_result IN BYTE MODE.
      lv_offset = lv_offset + 1.
    ENDDO.

  ENDMETHOD.

  METHOD get_blocks.
    rv_result = xstrlen( mv_buffer ) / 64.
  ENDMETHOD.

ENDCLASS.



CLASS lcl_hasher IMPLEMENTATION.

  METHOD constructor.
    super->constructor( ).

    mo_barrel = io_barrel.
    mo_buffer = io_buffer.
  ENDMETHOD.

  METHOD hash.
    DATA: ls_hash_def TYPE ty_hash_def.

    mo_barrel->reset( ).

    LOOP AT mt_hash_def INTO ls_hash_def.
      mo_barrel->set( hash_function( ls_hash_def ) ).
      mo_barrel->roll( ).
    ENDLOOP.

  ENDMETHOD.

  METHOD hash_function.
    DATA: lv_f TYPE f.

* (a + F(b,c,d) + X[k]) <<< s

    lv_f = mo_barrel->get( 0 ) +
      func( iv_x = mo_barrel->get( 1 )
            iv_y = mo_barrel->get( 2 )
            iv_z = mo_barrel->get( 3 ) ) +
      mo_buffer->get_word( is_def-word ) +
      mv_add.

    rv_result = overflow( lv_f ).
    rv_result = shift( iv_input  = rv_result
                       iv_places = is_def-shift ).

  ENDMETHOD.

ENDCLASS.


CLASS lcl_ff IMPLEMENTATION.

  METHOD constructor.
    super->constructor( io_barrel = io_barrel io_buffer = io_buffer ).

    mt_hash_def = VALUE #(
      ( word = 0 shift = 3 ) ( word = 1 shift = 7 ) ( word = 2 shift = 11 ) ( word = 3 shift = 19 )
      ( word = 4 shift = 3 ) ( word = 5 shift = 7 ) ( word = 6 shift = 11 ) ( word = 7 shift = 19 )
      ( word = 8 shift = 3 ) ( word = 9 shift = 7 ) ( word = 10 shift = 11 ) ( word = 11 shift = 19 )
      ( word = 12 shift = 3 ) ( word = 13 shift = 7 ) ( word = 14 shift = 11 ) ( word = 15 shift = 19 )
    ).

    mv_add = '000000'.

  ENDMETHOD.

  METHOD func.
* XY v not(X) Z

    rv_result = ( iv_x BIT-AND iv_y ) BIT-OR ( ( BIT-NOT iv_x ) BIT-AND iv_z ).

  ENDMETHOD.


ENDCLASS.


CLASS lcl_gg IMPLEMENTATION.

  METHOD constructor.
    super->constructor( io_barrel = io_barrel io_buffer = io_buffer ).

    mt_hash_def = VALUE #(
      ( word = 0 shift = 3 ) ( word = 4 shift = 5 ) ( word = 8 shift = 9 ) ( word = 12 shift = 13 )
      ( word = 1 shift = 3 ) ( word = 5 shift = 5 ) ( word = 9 shift = 9 ) ( word = 13 shift = 13 )
      ( word = 2 shift = 3 ) ( word = 6 shift = 5 ) ( word = 10 shift = 9 ) ( word = 14 shift = 13 )
      ( word = 3 shift = 3 ) ( word = 7 shift = 5 ) ( word = 11 shift = 9 ) ( word = 15 shift = 13 )
    ).

    mv_add = '5A827999'.

  ENDMETHOD.

  METHOD func.
* XY v XZ v YZ

    rv_result =
      ( iv_x BIT-AND iv_y ) BIT-OR
      ( iv_x BIT-AND iv_z ) BIT-OR
      ( iv_y BIT-AND iv_z ).

  ENDMETHOD.

ENDCLASS.


CLASS lcl_hh IMPLEMENTATION.

  METHOD constructor.
    super->constructor( io_barrel = io_barrel io_buffer = io_buffer ).

    mt_hash_def = VALUE #(
      ( word = 0 shift = 3 ) ( word = 8 shift = 9 ) ( word = 4 shift = 11 ) ( word = 12 shift = 15 )
      ( word = 2 shift = 3 ) ( word = 10 shift = 9 ) ( word = 6 shift = 11 ) ( word = 14 shift = 15 )
      ( word = 1 shift = 3 ) ( word = 9 shift = 9 ) ( word = 5 shift = 11 ) ( word = 13 shift = 15 )
      ( word = 3 shift = 3 ) ( word = 11 shift = 9 ) ( word = 7 shift = 11 ) ( word = 15 shift = 15 )
    ).

    mv_add = '6ED9EBA1'.
  ENDMETHOD.

  METHOD func.
* X xor Y xor Z

    rv_result = ( iv_x BIT-XOR iv_y ) BIT-XOR iv_z.

  ENDMETHOD.

ENDCLASS.





















*
