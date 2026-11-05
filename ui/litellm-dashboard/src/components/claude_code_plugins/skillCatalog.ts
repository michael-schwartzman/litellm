import { parseAsInteger, parseAsString, parseAsStringLiteral, useQueryStates } from "nuqs";
import { matchesSearchTerm } from "@/utils/searchUtils";

const SCAN_FILTERS = ["all", "yes", "no"] as const;
export type ScanFilter = (typeof SCAN_FILTERS)[number];

export interface SkillCatalogMetadata {
  created_by?: string | null;
  approved_by?: string | null;
  published_by?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  security_scan_passed?: boolean;
  keywords?: string[] | null;
}

const FILTER_PARSERS = {
  search: parseAsString.withDefault(""),
  tag: parseAsString.withDefault(""),
  scan: parseAsStringLiteral(SCAN_FILTERS).withDefault("all"),
  page: parseAsInteger.withDefault(1),
};
const FILTER_OPTIONS = {
  urlKeys: { search: "skills_search", tag: "skills_filter_tag", scan: "skills_filter_scan", page: "skills_page" },
};
const EMPTY_FILTERS = { search: null, tag: null, scan: null, page: null };

export function useSkillFilters() {
  const [filters, setFilters] = useQueryStates(FILTER_PARSERS, FILTER_OPTIONS);
  return {
    search: filters.search,
    tag: filters.tag,
    scan: filters.scan,
    setSearch: (search: string) => void setFilters({ search, page: null }),
    setTag: (tag: string) => void setFilters({ tag, page: null }),
    setScan: (scan: ScanFilter) => void setFilters({ scan, page: null }),
    clear: () => void setFilters(EMPTY_FILTERS),
    active: Boolean(filters.search.trim() || filters.tag || filters.scan !== "all"),
  };
}

export function skillTags(skills: SkillCatalogMetadata[]): string[] {
  return [...new Set(skills.flatMap((skill) => skill.keywords ?? []))].sort((a, b) => a.localeCompare(b));
}

export function matchesSkillFilters(
  skill: SkillCatalogMetadata & {
    name: string;
    description?: string | null;
    domain?: string | null;
    namespace?: string | null;
  },
  filters: { search: string; tag: string; scan: ScanFilter },
): boolean {
  const matchesQuery = matchesSearchTerm(filters.search, [
    skill.name,
    skill.description,
    skill.domain,
    skill.namespace,
    skill.created_by,
    skill.approved_by,
    skill.published_by,
    ...(skill.keywords ?? []),
  ]);
  const matchesTag =
    !filters.tag || (skill.keywords ?? []).some((tag) => tag.toLowerCase() === filters.tag.toLowerCase());
  const matchesScan = filters.scan === "all" || Boolean(skill.security_scan_passed) === (filters.scan === "yes");
  return matchesQuery && matchesTag && matchesScan;
}
