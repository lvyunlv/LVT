# libelgl/CMakeLists.txt
file(GLOB_RECURSE LIBELGL_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/elgl/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/elgloffline/*.cpp"
)

add_library(libelgl STATIC ${LIBELGL_SRC})

target_include_directories(libelgl PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/elgl
    ${CMAKE_CURRENT_SOURCE_DIR}/elgloffline
)

# 链接你依赖的库，例如 MCL / OpenFHE（根据需要补全）
target_link_libraries(libelgl PUBLIC mcl)  # 视情况而定
