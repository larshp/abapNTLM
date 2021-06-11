REPORT zntlm_test.

PARAMETERS: p_get    TYPE xfeld RADIOBUTTON GROUP 1,
            p_post   TYPE xfeld RADIOBUTTON GROUP 1,
            p_url    TYPE text100,
            p_user   TYPE text20,
            p_passw  TYPE text20,
            p_domain TYPE text20,
            p_workst TYPE text20,
            p_ct     TYPE text50,
            p_body   TYPE text100.

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
        lv_string TYPE string,
        lt_fields TYPE tihttpnvp.

  FIELD-SYMBOLS: <ls_field> LIKE LINE OF lt_fields.

  IF p_get = 'X'.
    li_client = zcl_ntlm=>get( iv_username = p_user
                               iv_password = p_passw
                               iv_domain   = p_domain
                               iv_workstation = p_workst
                               iv_url      = p_url ).
  ENDIF.

  IF p_post = 'X'.
    li_client = zcl_ntlm=>post( iv_username = p_user
                                iv_password = p_passw
                                iv_domain   = p_domain
                                iv_workstation = p_workst
                                iv_url      = p_url
                                iv_content_type = p_ct
                                iv_body = p_body ).
  ENDIF.

  li_client->response->get_header_fields( CHANGING fields = lt_fields ).
  lv_string = li_client->response->get_cdata( ).
  li_client->close( ).

  LOOP AT lt_fields ASSIGNING <ls_field>.
    WRITE: / <ls_field>-name, 25 <ls_field>-value.
  ENDLOOP.

  WRITE: /.

  WHILE strlen( lv_string ) > 100.
    WRITE: / lv_string(100).
    lv_string = lv_string+100.
  ENDWHILE.
  WRITE: / lv_string.

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
