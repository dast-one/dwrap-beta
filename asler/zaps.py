from dataclasses import asdict, dataclass, field


@dataclass
class ZapAlert:
    """..."""
    method: str
    path: str
    query: str
    body: str


@dataclass
class ZapSite:
    """..."""
    method: str
    path: str
    query: str
    body: str


@dataclass
class ZapReport:
    """..."""
    version: str = 'x3'
    generated: str = field(default_factory=lambda: datetime.now().ctime())
    site: list[ZapSite] = field(default_factory=list)


def as_custom_dict(zap_report):
    return {
        '@version': zap_report.version,
        '@generated': zap_report.generated,
        'site': zap_report.site,
    }


asdict(ZapReport(), dict_factory=as_custom_dict)

