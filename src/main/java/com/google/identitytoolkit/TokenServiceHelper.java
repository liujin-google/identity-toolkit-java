/*
 * Copyright 2014 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.identitytoolkit;

import com.google.gson.JsonObject;

import net.oauth.jsontoken.Checker;
import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.JsonTokenParser;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.discovery.VerifierProviders;

import java.security.SignatureException;

/**
 * Helper to verify the access token from Token Service.
 */
public class TokenServiceHelper {
  public static final String ID_TOKEN_EMAIL = "email";
  public static final String ID_TOKEN_USER_ID = "user_id";
  public static final String SUB_FIELD = "sub";
  private final JsonTokenParser parser;

  public TokenServiceHelper(String audience, RpcHelper rpcHelper) {
    super();
    VerifierProviders verifierProviders = new VerifierProviders();
    verifierProviders.setVerifierProvider(SignatureAlgorithm.RS256,
        new TokenServiceVerifierManager(rpcHelper));
    parser = new JsonTokenParser(verifierProviders, new AudienceChecker(audience));
  }

  public JsonToken verifyAndDeserialize(String token)
      throws SignatureException {
    return parser.verifyAndDeserialize(token);
  }

  /**
   * Checks the token is indeed for this RP.
   */
  public static class AudienceChecker implements Checker {

    private final String expectedAudience;

    public AudienceChecker(String audience) {
      this.expectedAudience = audience;
    }

    @Override
    public void check(JsonObject payload) throws SignatureException {
      if (!payload.has(SUB_FIELD)) {
        throw new SignatureException("No sub field in payload.");
      }
      String subject = payload.get(SUB_FIELD).getAsString();
      if (!expectedAudience.split("[-\\.]")[0].equals(subject.split("[-@]")[0])) {
        throw new SignatureException(String.format(
            "Subject prefix mismatch: %s. Should start with: %s", subject, expectedAudience));
      }
    }
  }
}
