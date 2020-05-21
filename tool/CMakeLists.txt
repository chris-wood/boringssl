include_directories(../include)

add_executable(
  bssl

  args.cc
  ciphers.cc
  client.cc
  const.cc
  digest.cc
  file.cc
  generate_ed25519.cc
  genrsa.cc
  pkcs12.cc
  rand.cc
  server.cc
  sign.cc
  speed.cc
  tool.cc
  transport_common.cc

  #../third_party/blake3/c/blake3.c
  #../third_party/blake3/c/blake3_dispatch.c
  #../third_party/blake3/c/blake3_portable.c
  #../third_party/blake3/c/blake3_sse41_x86-64_unix.S
  #../third_party/blake3/c/blake3_avx2_x86-64_unix.S
  #../third_party/blake3/c/blake3_avx512_x86-64_unix.S
)

add_dependencies(bssl global_target)

if(APPLE OR WIN32 OR ANDROID)
  target_link_libraries(bssl ssl crypto)
else()
  find_library(FOUND_LIBRT rt)
  if(FOUND_LIBRT)
    target_link_libraries(bssl ssl crypto -lrt)
  else()
    target_link_libraries(bssl ssl crypto)
  endif()
endif()
