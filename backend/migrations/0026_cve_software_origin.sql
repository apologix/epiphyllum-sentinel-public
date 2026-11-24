ALTER TABLE services ADD COLUMN software_origin text CHECK(software_origin IN ('operator','banner'));
