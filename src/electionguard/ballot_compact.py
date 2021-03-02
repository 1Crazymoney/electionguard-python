from dataclasses import dataclass
from typing import Dict, List

from electionguard.group import int_to_q_unchecked

from .ballot import (
    SubmittedBallot,
    ExtendedData,
    PlaintextBallot,
    PlaintextBallotContest,
    PlaintextBallotSelection,
    create_ballot_hash,
)
from .ballot_box import BallotBoxState
from .election import (
    CiphertextElectionContext,
    ContestDescriptionWithPlaceholders,
    InternalElectionDescription,
)
from .encrypt import encrypt_ballot_contests
from .utils import get_optional


@dataclass
class CompactPlaintextBallot:
    """A compact plaintext representation of ballot minimized for data size"""

    object_id: str
    style_id: str
    selections: List[bool]
    extra_data: Dict[int, ExtendedData]


@dataclass
class CompactSubmittedBallot:
    """A compact submitted ballot minimized for data size"""

    compact_plaintext_ballot: CompactPlaintextBallot
    timestamp: int
    ballot_nonce: int
    previous_tracking_hash: int
    tracking_hash: int
    ballot_box_state: BallotBoxState


def expand_compact_submitted_ballot(
    compact_ballot: CompactSubmittedBallot,
    description: InternalElectionDescription,
    context: CiphertextElectionContext,
) -> SubmittedBallot:
    """
    Expand a compact submitted ballot using context and
    the election description into a submitted ballot
    """
    # Convert to Q from int
    tracking_hash = int_to_q_unchecked(compact_ballot.tracking_hash)
    previous_tracking_hash = int_to_q_unchecked(compact_ballot.previous_tracking_hash)
    ballot_nonce = int_to_q_unchecked(compact_ballot.ballot_nonce)

    # Expand ballot and encrypt & hash contests
    plaintext_ballot = expand_compact_plaintext_ballot(
        compact_ballot.compact_plaintext_ballot, description
    )
    contests = get_optional(
        encrypt_ballot_contests(plaintext_ballot, description, context, ballot_nonce)
    )
    crypto_hash = create_ballot_hash(
        plaintext_ballot.object_id, description.description_hash, contests
    )

    return SubmittedBallot(
        plaintext_ballot.object_id,
        plaintext_ballot.ballot_style,
        description.description_hash,
        previous_tracking_hash,
        contests,
        tracking_hash,
        compact_ballot.timestamp,
        crypto_hash,
        ballot_nonce,
        compact_ballot.ballot_box_state,
    )


def expand_compact_plaintext_ballot(
    compact_ballot: CompactPlaintextBallot, description: InternalElectionDescription
) -> PlaintextBallot:
    """Expand a compact plaintext ballot into the original plaintext ballot"""
    return PlaintextBallot(
        compact_ballot.object_id,
        compact_ballot.style_id,
        _get_plaintext_contests(compact_ballot, description),
    )


def _get_plaintext_contests(
    compact_ballot: CompactPlaintextBallot, description: InternalElectionDescription
) -> List[PlaintextBallotContest]:
    """Get ballot contests from compact plaintext ballot"""
    index = 0
    ballot_style_contests = _get_ballot_style_contests(
        compact_ballot.style_id, description
    )

    contests: List[PlaintextBallotContest] = []
    for description_contest in sorted(
        description.contests, key=lambda c: c.sequence_order
    ):
        contest_in_style = (
            ballot_style_contests.get(description_contest.object_id) is not None
        )

        # Iterate through selections. If contest not in style, mark placeholder
        selections: List[PlaintextBallotSelection] = []
        for selection in sorted(
            description_contest.ballot_selections, key=lambda s: s.sequence_order
        ):
            selections.append(
                PlaintextBallotSelection(
                    selection.candidate_id,
                    compact_ballot.selections[index],
                    not contest_in_style,
                    compact_ballot.extra_data.get(index),
                )
            )
            index += 1

        contests.append(
            PlaintextBallotContest(description_contest.object_id, selections)
        )
    return contests


def _get_ballot_style_contests(
    style_id: str, description: InternalElectionDescription
) -> Dict[str, ContestDescriptionWithPlaceholders]:
    ballot_style_contests = description.get_contests_for(style_id)
    return {contest.object_id: contest for contest in ballot_style_contests}
