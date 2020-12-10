import itertools
import mimetypes
import typing
import os
from pathlib import Path
from mitmproxy import ctx, exceptions, http, version
from mitmproxy.script import concurrent

# Addon similar to built-in MapLocal with following notable differences
# - use @concurrent to avoid reading files in event loop thread
# - no guessing of mime-type (could be re-added, ideally not at response time)
# - option to respond with 404 on unknown URLs
# - exact match on urls via dict lookup rather than regex matching against every mapping
# - only GET and HEAD support for now, and no support for flow filters
# - only support for single files per mapping
# - ability to specify mapping list via a file

class MapLocal2Spec(typing.NamedTuple):
  url: str
  local_path: Path

def parse_map_local2_spec(option: str) -> MapLocal2Spec:
  sep, rem = option[0], option[1:]
  url, path = rem.split(sep)
  if not Path(path).is_file():
    raise exceptions.OptionsError(f"Missing path for {url}: {path}")
  local_path = Path(path).expanduser().resolve(strict=True)
  return MapLocal2Spec(url, local_path)

class MapLocal2:
  OPTION_MAPPING = "map_local2"
  OPTION_MAPPING_FILE = "map_local2_file"
  OPTION_404 = "map_local2_404"
  def __init__(self):
    self.replacements: typing.Dict[str, MapLocal2Spec] = {}
    self.map404 = False
  def load(self, loader):
    loader.add_option(
        self.OPTION_MAPPING, typing.Sequence[str], [],
        """
        Map remote resources to a local file using a mapping of the form
        "/url/file", where the separator can be any character.
        """
    )
    loader.add_option(
        self.OPTION_MAPPING_FILE, typing.Sequence[str], [],
        """
        Map remote resources to a local files using mappings of the form
        "/url/file", where the separator can be any character.
        One mapping per line.
        """
    )
    loader.add_option(
        self.OPTION_404, bool, False,
        """
        Respond with 404 to unknown urls.
        """
    )
  def configure(self, updated):
    if self.OPTION_404 in updated:
      self.map404 = getattr(ctx.options, self.OPTION_404)
    if self.OPTION_MAPPING in updated or self.OPTION_MAPPING_FILE in updated:
      self.replacements = {}
      try:
        fileargs = getattr(ctx.options, self.OPTION_MAPPING_FILE) or []
        filelist = itertools.chain(*[filter(None, Path(f).read_text().splitlines()) for f in fileargs])
        arglist = getattr(ctx.options, self.OPTION_MAPPING) or []
        for option in itertools.chain(filelist, arglist):
          spec = parse_map_local2_spec(option)
          if spec.url in self.replacements and not spec.local_path == self.replacements[spec.url].local_path:
            raise exceptions.OptionsError(f"Conflicting paths for {spec.url}: {spec.local_path} {self.replacements[spec.url].local_path}")
          self.replacements[spec.url] = spec
      except Exception as e:
        raise exceptions.OptionsError(f"Cannot parse map_local2 options: {e}") from e
  @concurrent
  def request(self, flow: http.HTTPFlow) -> None:
    if flow.reply and flow.reply.has_message:
      return
    url = flow.request.pretty_url
    if not flow.request.method in ["GET", "HEAD"] or not url in self.replacements:
      if self.map404:
        flow.response = http.HTTPResponse.make(404)
      return
    _, local_file = self.replacements[url]
    headers = {
      "Server": version.MITMPROXY
    }
    if flow.request.method == "HEAD":
      contents = ""
    else:
      contents = local_file.read_bytes()
    flow.response = http.HTTPResponse.make(
        200,
        contents,
        headers
    )

addons = [MapLocal2()]
