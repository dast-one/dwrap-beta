FROM projectdiscovery/nuclei

RUN nuclei -update-templates
ENTRYPOINT [ "nuclei", "-ni", "-duc" ]
