REPORT zntlm_test.

PARAMETERS: p_url    TYPE text100,
            p_user   TYPE text20,
            p_passw  TYPE text20,
            p_domain TYPE text20.

INITIALIZATION.
  PERFORM initialization.

START-OF-SELECTION.
  PERFORM run.

*&---------------------------------------------------------------------*
*&      Form  run
*&---------------------------------------------------------------------*
*       text
*----------------------------------------------------------------------*
FORM run RAISING cx_static_check.

  DATA: li_client TYPE REF TO if_http_client,
        lt_fields TYPE tihttpnvp.

  FIELD-SYMBOLS: <ls_field> LIKE LINE OF lt_fields.


  li_client = zcl_ntlm=>get( iv_username = p_user
                             iv_password = p_passw
                             iv_domain   = p_domain
                             iv_url      = p_url ).
  li_client->response->get_header_fields( CHANGING fields = lt_fields ).
  li_client->close( ).

  LOOP AT lt_fields ASSIGNING <ls_field>.
    WRITE: / <ls_field>-name, 25 <ls_field>-value.
  ENDLOOP.

ENDFORM.                    "run

*&---------------------------------------------------------------------*
*&      Form  initialization
*&---------------------------------------------------------------------*
*       text
*----------------------------------------------------------------------*
FORM initialization.

  CALL FUNCTION 'RS_SUPPORT_SELECTIONS'
    EXPORTING
      report               = sy-cprog
      variant              = 'DEFAULT'
    EXCEPTIONS
      variant_not_existent = 01
      variant_obsolete     = 02
      ##fm_subrc_ok.

ENDFORM.                    "initialization