# Server-side implementation plan: Calendar delegation (`nextcloud/server`)

## Context

The `GVodyanov/calendar` frontend already implements the full delegation UI on top of the
CalDAV proxy-principal system. Two gaps in `nextcloud/server` must be closed before the
feature is end-to-end functional. Everything else (database layer, `group-member-set`
read/write, `group-membership`, individual Calendar ACL, user search) is already
implemented.

---

## Scope — exactly two files must change

| # | File | What to add |
|---|------|-------------|
| 1 | `apps/dav/lib/CalDAV/CalendarHome.php` | Override `getACL()` to grant `{DAV:}read` to the owner's `calendar-proxy-write` and `calendar-proxy-read` sub-principals |
| 2 | `apps/dav/lib/Connector/Sabre/Principal.php` | Return an explicit `{DAV:}acl` for proxy-group principals so only the owner can PROPPATCH them |

Do **not** modify any other file unless a test fixture requires it.

---

## Change 1 — `apps/dav/lib/CalDAV/CalendarHome.php`

### Problem

`\Sabre\CalDAV\CalendarHome` (the Sabre parent class) only grants `{DAV:}read` and
`{DAV:}write` privileges to the calendar home's own principal URI. A delegate user
calling:

```
PROPFIND /remote.php/dav/calendars/{delegatorUserId}/
```

receives **403 Forbidden** because the ACL plugin finds no matching rule for the
delegate's principal.

Individual `Calendar` objects already grant proxy principals read/write access (added in
server PR #16666), but the `CalendarHome` container never received the same treatment.

### Implementation

Add a `getACL()` override **inside** the `OCA\DAV\CalDAV\CalendarHome` class body
(after the existing `getChild()` method and before `calendarSearch()`):

```php
/**
 * @inheritdoc
 *
 * Extends the default ACL to grant proxy principals access to list this
 * calendar home. Individual Calendar objects already have their own proxy
 * ACL entries; this entry allows the PROPFIND on the home collection itself.
 *
 * @return array
 */
public function getACL(): array {
    $acl = parent::getACL();
    $ownerPrincipal = $this->principalInfo['uri'];

    // Write-proxy delegates may list and read the calendar home so they can
    // discover which calendars are available.
    $acl[] = [
        'privilege' => '{DAV:}read',
        'principal' => $ownerPrincipal . '/calendar-proxy-write',
        'protected' => true,
    ];
    // Read-proxy delegates may also list the calendar home.
    $acl[] = [
        'privilege' => '{DAV:}read',
        'principal' => $ownerPrincipal . '/calendar-proxy-read',
        'protected' => true,
    ];

    return $acl;
}
```

### Why only `{DAV:}read` on the home?

`{DAV:}write` on the home would allow creating new calendars on behalf of the owner,
which is out of scope for this feature. Delegates can already read and write events
inside individual calendars via the Calendar-level ACL.

### Tests to add

File: `apps/dav/tests/unit/CalDAV/CalendarHomeTest.php`

1. **`testGetAclContainsProxyWritePrincipal`** — assert that the returned ACL array
   contains an entry `{ privilege: '{DAV:}read', principal: 'principals/users/alice/calendar-proxy-write' }`.
2. **`testGetAclContainsProxyReadPrincipal`** — same for `calendar-proxy-read`.
3. **Integration / functional test** (optional but recommended): create a request as
   user `bob` who is in `alice/calendar-proxy-write`, assert HTTP 207 on
   `PROPFIND /dav/calendars/alice/`.

---

## Change 2 — `apps/dav/lib/Connector/Sabre/Principal.php`

### Problem

`getPrincipalPropertiesByPath()` currently returns only `['uri' => '...']` for proxy
group paths like `principals/users/alice/calendar-proxy-write`. Because no ACL is
attached, Sabre's ACL plugin falls back to a permissive server-default that may allow
any authenticated user to call PROPPATCH on another user's proxy group, effectively
letting `bob` add or remove `alice`'s delegates.

### Implementation

In the existing block that handles `$name === 'calendar-proxy-write' || $name === 'calendar-proxy-read'`
inside `getPrincipalPropertiesByPath()`, extend the returned array with an explicit
`{DAV:}acl` key:

**Before:**
```php
if ($name === 'calendar-proxy-write' || $name === 'calendar-proxy-read') {
    [$prefix2, $name2] = \Sabre\Uri\split($prefix);

    if ($prefix2 === $this->principalPrefix) {
        $user = $this->userManager->get($name2);

        if ($user !== null) {
            return [
                'uri' => 'principals/users/' . $user->getUID() . '/' . $name,
            ];
        }
        return null;
    }
}
```

**After:**
```php
if ($name === 'calendar-proxy-write' || $name === 'calendar-proxy-read') {
    [$prefix2, $name2] = \Sabre\Uri\split($prefix);

    if ($prefix2 === $this->principalPrefix) {
        $user = $this->userManager->get($name2);

        if ($user !== null) {
            return [
                'uri' => 'principals/users/' . $user->getUID() . '/' . $name,
                // Only the principal owner may modify their own proxy group.
                // Any authenticated user may read it (needed by Sabre internals).
                '{DAV:}acl' => [
                    [
                        'privilege' => '{DAV:}read',
                        'principal' => '{DAV:}authenticated',
                        'protected' => true,
                    ],
                    [
                        'privilege' => '{DAV:}write',
                        'principal' => 'principals/users/' . $user->getUID(),
                        'protected' => true,
                    ],
                ],
            ];
        }
        return null;
    }
}
```

### Tests to add

File: `apps/dav/tests/unit/Connector/Sabre/PrincipalTest.php`

1. **`testGetProxyPrincipalHasAcl`** — call `getPrincipalByPath('principals/users/alice/calendar-proxy-write')`,
   assert the returned array contains key `{DAV:}acl` with exactly two entries
   (authenticated-read + owner-write).
2. **`testProxyGroupWriteRequiresOwner`** — integration test: as user `bob` attempt
   `PROPPATCH /dav/principals/users/alice/calendar-proxy-write` to add `bob` as a
   delegate of `alice`; assert HTTP 403.
3. **`testProxyGroupWriteAllowedForOwner`** — as user `alice` attempt the same PROPPATCH;
   assert HTTP 207.

---

## SPDX headers

All new or substantially modified PHP file blocks must use year **2026**:

```php
/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
```

---

## Already working — do NOT change

The following are fully implemented and must not be modified:

| DAV operation | Server class | Notes |
|---|---|---|
| `PROPFIND` proxy-group → `group-member-set` | `PrincipalProxyTrait::getGroupMemberSet` | Returns current delegates |
| `PROPPATCH` proxy-group ← `group-member-set` | `PrincipalProxyTrait::setGroupMemberSet` | Adds / removes delegates |
| `PROPFIND` principal → `group-membership` | `PrincipalProxyTrait::getGroupMembership` | Returns proxy groups the user belongs to |
| Calendar event read/write for delegate | `Calendar::getACL()` | Updated in server PR #16666 |
| User principal search (add-delegate dialog) | `Principal::searchPrincipals` | Used by the frontend NcSelect |
| `dav_cal_proxy` table | `ProxyMapper` + `Proxy` entity | Database layer already complete |

---

## Verification checklist

After implementing both changes, the following end-to-end flow must work:

1. User **alice** opens the Delegation modal in the calendar app and adds **bob** as a delegate.
   - `PROPPATCH /dav/principals/users/alice/calendar-proxy-write` succeeds (HTTP 207).
2. User **bob** logs in; the calendar app calls `fetchDelegators()` which reads
   `PROPFIND /dav/principals/users/bob` → `group-membership` and finds `alice/calendar-proxy-write`.
3. The app calls `fetchDelegatedCalendars()` which does
   `PROPFIND /dav/calendars/alice/` — this now succeeds (HTTP 207) because of **Change 1**.
4. Bob can see Alice's calendars in the "Delegated" section of the sidebar.
5. Bob can create/edit events in Alice's calendars (existing Calendar ACL already handles this).
6. Alice revokes Bob's access — `PROPPATCH` removes Bob from the proxy group.
7. User **charlie** (unrelated) cannot modify Alice's proxy group — `PROPPATCH` returns 403
   because of **Change 2**.
