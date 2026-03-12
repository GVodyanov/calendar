# Server-side implementation plan: Calendar delegation (`nextcloud/server`)

## Context

The `GVodyanov/calendar` frontend already implements the full delegation UI on top of the
CalDAV proxy-principal system. Three gaps in `nextcloud/server` must be closed before the
feature is end-to-end functional. Everything else (database layer, `group-member-set`
read/write, `group-membership`, individual Calendar ACL, user search) is already
implemented.

---

## ✅ Will delegated calendars appear in the delegate's sidebar?

**Yes.** Here is the exact data-flow that proves it:

```
[Alice adds Bob as delegate]
  → PROPPATCH /dav/principals/users/alice/calendar-proxy-write
      sets group-member-set = [.../principals/users/bob]   ← already works

[Bob logs into the calendar app]
  → fetchDelegators()
      PROPFIND /dav/principals/users/bob  → group-membership
      finds: principals/users/alice/calendar-proxy-write
      stores: delegatorUserIds = ['alice']

  → fetchDelegatedCalendars()  (for each delegatorUserId)
      PROPFIND /dav/calendars/alice/       ← BLOCKED today (403)
      ↑ Fixed by Change 1 below (CalendarHome.getACL)   → 207 OK
      maps each calendar → { ...calendarObj, isDelegated: true }
      pushes into calendarsStore

[CalendarList.vue renders]
  → "Delegated" section shows all calendars where isDelegated === true
  → Bob sees Alice's calendars in his sidebar ✓
```

Without Change 1 the `PROPFIND /dav/calendars/alice/` step returns **403 Forbidden** and
no calendars are loaded. With Change 1 it returns **207 Multi-Status** and all of Alice's
calendars populate the "Delegated" section of Bob's sidebar.

---

## Scope — three changes required

| # | File | What to add |
|---|------|-------------|
| 1 | `apps/dav/lib/CalDAV/CalendarHome.php` | Override `getACL()` to grant `{DAV:}read` to the owner's `calendar-proxy-write` and `calendar-proxy-read` sub-principals |
| 2 | `apps/dav/lib/Connector/Sabre/Principal.php` | Return an explicit `{DAV:}acl` for proxy-group principals so only the owner can PROPPATCH them |
| 3 | `apps/dav/lib/Connector/Sabre/Principal.php` | Detect newly added delegates inside `updatePrincipal()` and send a notification email via `OCP\Mail\IMailer` |

Do **not** modify any other file unless a test fixture or DI container wiring requires it.

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

## Change 3 — Email notification when a delegate is added (`apps/dav/lib/Connector/Sabre/Principal.php`)

### Problem

When Alice adds Bob as a delegate, Bob has no way of knowing until he logs in. An
automated email notification ("You have been granted delegate access to Alice's calendars")
lets Bob act immediately and avoids confusion.

### Where to hook

`Principal.php` already handles `PROPPATCH` on proxy-group principals through the
`updatePrincipal()` method (or the method that calls `setGroupMemberSet` on the
`ProxyMapper`). After writing the new member set to the database, compare the old
membership list with the new one and send an email to every **newly added** member.

### Constructor changes

Add `OCP\Mail\IMailer` and `OCP\IUserManager` and `OCP\IL10N` (or
`OCP\L10N\IFactory`) to the constructor's injected dependencies:

```php
public function __construct(
    // ... existing parameters ...
    private IMailer $mailer,
    private IUserManager $userManager,
    private IFactory $l10nFactory,
) {}
```

> These services are already available in the DAV app's DI container. No new
> container registrations are needed.

### Implementation — diff inside `updatePrincipal()` (or equivalent proxy-write method)

```php
// Immediately before writing the new member set, snapshot the old set:
$oldMembers = $this->proxyMapper->getProxiesOf($ownerUid, Proxy::PERMISSION_WRITE);
$oldMemberUids = array_column($oldMembers, 'proxyId');

// ... existing write call, e.g.:
$this->proxyMapper->setProxiesOf($ownerUid, $newMemberUids, Proxy::PERMISSION_WRITE);

// After the write, find newly added members and notify them:
$addedUids = array_diff($newMemberUids, $oldMemberUids);
foreach ($addedUids as $delegateUid) {
    $this->sendDelegationNotification($ownerUid, $delegateUid);
}
```

Add the private helper method to the same class:

```php
/**
 * Send an email to a newly added delegate informing them of the delegation.
 *
 * @param string $ownerUid  User ID of the calendar owner who granted access
 * @param string $delegateUid User ID of the user who was just granted access
 */
private function sendDelegationNotification(string $ownerUid, string $delegateUid): void {
    $delegateUser = $this->userManager->get($delegateUid);
    $ownerUser    = $this->userManager->get($ownerUid);

    if ($delegateUser === null || $ownerUser === null) {
        return;
    }

    $delegateEmail = $delegateUser->getEMailAddress();
    if ($delegateEmail === null || $delegateEmail === '') {
        return; // No email address on file — skip silently.
    }

    $l = $this->l10nFactory->get('dav');

    $ownerDisplayName    = $ownerUser->getDisplayName() ?: $ownerUid;
    $delegateDisplayName = $delegateUser->getDisplayName() ?: $delegateUid;

    $subject = $l->t('%s has granted you access to their calendars', [$ownerDisplayName]);
    $bodyText = $l->t(
        'Hello %1$s,

%2$s has added you as a calendar delegate. You can now view and manage their
calendars in the Nextcloud Calendar app under the "Delegated" section.

To remove yourself as a delegate, ask %2$s to revoke your access in their
Calendar settings.',
        [$delegateDisplayName, $ownerDisplayName]
    );

    try {
        $message = $this->mailer->createMessage();
        $message->setTo([$delegateEmail => $delegateDisplayName]);
        $message->setSubject($subject);
        $message->setPlainBody($bodyText);
        $this->mailer->send($message);
    } catch (\Exception $e) {
        // Notification failure must never block the PROPPATCH response.
        $this->logger->warning(
            'Could not send delegation notification email',
            ['owner' => $ownerUid, 'delegate' => $delegateUid, 'error' => $e->getMessage()]
        );
    }
}
```

### Important constraints

* **Never throw** from `sendDelegationNotification`. A failed email must not cause the
  PROPPATCH to return an error — the delegation itself succeeded.
* Only send notifications for **newly added** members (diff old vs new set). Do **not**
  send on revocation; that is handled by the UI.
* Respect privacy: only the delegate's own email address is used. Do not expose the
  owner's email in the notification unless it is already part of the user's public
  profile.

### Tests to add

File: `apps/dav/tests/unit/Connector/Sabre/PrincipalTest.php`

1. **`testDelegationNotificationEmailIsSentToNewDelegate`** — mock `IMailer::send()` to
   expect exactly one call; mock `IUserManager` to return valid users with email
   addresses; call the proxy-write PROPPATCH with a net-new member; assert `send()` was
   called once with the correct recipient and subject.
2. **`testDelegationNotificationNotSentForExistingDelegate`** — add bob to alice's group
   twice; assert `send()` is called only on the first invocation.
3. **`testDelegationNotificationSkippedWhenNoEmail`** — set `getEMailAddress()` to return
   `null`; assert `send()` is never called.
4. **`testDelegationNotificationFailureDoesNotBlockProppatch`** — make `IMailer::send()`
   throw a `\RuntimeException`; assert that `updatePrincipal()` still returns without
   throwing and that the proxy row was written to the database.

---

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

After implementing all three changes, the following end-to-end flow must work:

1. User **alice** opens the Delegation modal in the calendar app and adds **bob** as a delegate.
   - `PROPPATCH /dav/principals/users/alice/calendar-proxy-write` succeeds (HTTP 207).
   - **Bob receives an email**: "Alice has granted you access to their calendars" ← **Change 3**.
2. User **bob** logs in; the calendar app calls `fetchDelegators()` which reads
   `PROPFIND /dav/principals/users/bob` → `group-membership` and finds `alice/calendar-proxy-write`.
3. The app calls `fetchDelegatedCalendars()` which does
   `PROPFIND /dav/calendars/alice/` — this now succeeds (HTTP 207) because of **Change 1**.
4. **Bob can see Alice's calendars in the "Delegated" section of his sidebar** ← confirmed by Change 1 + frontend store.
5. Bob can create/edit events in Alice's calendars (existing Calendar ACL already handles this).
6. Alice revokes Bob's access — `PROPPATCH` removes Bob from the proxy group (no email sent on revocation).
7. User **charlie** (unrelated) cannot modify Alice's proxy group — `PROPPATCH` returns 403
   because of **Change 2**.
