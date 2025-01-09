#!/bin/bash -xe

for i in $(seq 1 300);
do
    ../build-freerdp-qt6_clang-Debug/Testing/TestPrimitives TestPrimitivesYUV
done
