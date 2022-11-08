"Rule to run wasm-opt"

def _wasm_opt_impl(ctx):
    binaryen_toolchain = ctx.toolchains["//binaryen:toolchain_type"]

    output_files = []

    for src in ctx.attr.srcs:
        for file in src.files.to_list():
            output = ctx.actions.declare_file(ctx.label.name + "/" + file.basename)
            output_files.append(output)

            if file.extension == "wasm":
                args = ctx.actions.args()
                args.add(file.path)
                args.add("-Oz")
                args.add_all(["-o", output.path])

                ctx.actions.run(
                    executable = binaryen_toolchain.wasm_opt_path,
                    inputs = [file],
                    outputs = [output],
                    arguments = [args],
                )
            else:
                ctx.actions.run_shell(
                    tools = [file],
                    outputs = [output],
                    command = "cp -f \"$1\" \"$2\"",
                    arguments = [file.path, output.path],
                )

    return DefaultInfo(files = depset(output_files))

wasm_opt = rule(
    implementation = _wasm_opt_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
    },
    toolchains = ["//binaryen:toolchain_type"],
)
