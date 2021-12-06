# Tracer

Tracer is used to collect traces of the consumer programs.
Its output is the trace files.

# Usage

You need to run header analysis tool first since it not only generates complementary tracer code for the give attack surface but also provides the meta information json file which is another input required by the tracer.

The `libhook-audio.mm`, `libhook-font.mm`, `libhook-image.mm`, `libhook-rtf.mm`, `libhook-cgpdf.mm` are tracers generated by header analysis tool.
To trace, rename any of the above as `libhook.mm`, rename the generated meta information json file as `input.json`, and run the correpsonding bash script.

```bash
# e.g., to trace image APIs, you can use the following commands:
cp libhook-image.mm libhook.mm
# copy the meta information json file generated by header analysis tool
cp headerpp_image.json input.json
# use 
bash run_image.sh
```
