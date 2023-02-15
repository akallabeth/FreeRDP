
add_executable(
  convert_font_to_c
  convert_font_to_c.c
)

add_library(font OBJECT
  opensans_variable_font.h
  opensans_variable_font.c
  font_writer.h
  font_writer.c
)
set_property(TARGET font PROPERTY POSITION_INDEPENDENT_CODE ON)
